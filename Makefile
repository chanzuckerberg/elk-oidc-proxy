# infra variables
SEC_GROUP_ID=$(shell aws ec2 describe-security-groups | jq -r '.SecurityGroups[] | select(.GroupName == "$(APP_NAME)") | .GroupId')
TARGET_GROUP_ARN=$(shell aws elbv2 describe-target-groups | jq -r '.TargetGroups[] | select(.TargetGroupName == "$(APP_NAME)") | .TargetGroupArn')
IMAGE_NAME=$(shell terraform output ecr_uri)
SUBNETS=$(shell terraform output subnets | tr '\n' ' ')
SEC_GROUP=$(shell terraform output security_group)

.PHONY: clean
clean:
	rm -f Dockerfile
	rm -rf .terraform

.PHONY: init
init: clean
	terraform init \
		-backend-config bucket=$(TERRAFORM_BUCKET) \
		-backend-config profile=$(AWS_PROFILE) \
		-backend-config region=$(AWS_DEFAULT_REGION)

.PHONY: dockerfile
dockerfile:
	cat Dockerfile.template | envsubst '$$HEALTHCHECK_ACCOUNT_EMAIL $$PROXY_FQDN $$ES_ENDPOINT $$OAUTH2_CLIENT_ID $$OAUTH2_CLIENT_SECRET $$ACCOUNT_ID' > Dockerfile

.PHONY: image
image: dockerfile
	docker build -t $(APP_NAME) .

.PHONY: publish
publish:
	docker tag $(APP_NAME):latest $(IMAGE_NAME)
	docker push $(IMAGE_NAME)

.PHONY: service
service:
	aws ecs register-task-definition --cli-input-json '$(shell terraform output task_definition)'
	aws ecs create-service \
		--service-name $(APP_NAME) \
		--desired-count 0 \
		--cluster $(CLUSTER) \
		--task-definition $(APP_NAME) \
		--network-configuration "awsvpcConfiguration={subnets=[$(SUBNETS)],securityGroups=[$(SEC_GROUP)],assignPublicIp=ENABLED}" \
		--load-balancers targetGroupArn=$(TARGET_GROUP_ARN),containerName=$(APP_NAME),containerPort=$(PORT) \
		--launch-type FARGATE

.PHONY: deploy
deploy:
	aws ecs update-service \
		--cluster $(CLUSTER) \
		--service $(APP_NAME) \
		--task-definition $(APP_NAME) \
		--desired-count 1 \
		--force-new-deployment

.PHONY: scale-down
scale-down:
	aws ecs list-services \
		--cluster $(CLUSTER) | \
		jq -r .serviceArns[] | \
		xargs aws ecs update-service --cluster $(CLUSTER) --desired-count 0 --service
	aws ecs list-tasks \
		--cluster $(CLUSTER) \
		--family $(APP_NAME) | \
		jq -r .taskArns[] | \
		xargs aws ecs stop-task --cluster $(CLUSTER) --task

.PHONY: delete-service
delete-service: scale-down
	aws ecs list-services \
		--cluster $(CLUSTER) | \
		jq -r .serviceArns[] | \
		xargs aws ecs delete-service --cluster $(CLUSTER) --service
