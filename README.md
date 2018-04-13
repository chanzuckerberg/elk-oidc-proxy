# ELK OIDC Proxy for AWS ElasticSearch
ELK OIDC Proxy uses Google accounts authenticate users to use [AWS ElasticSearch](https://aws.amazon.com/elasticsearch-service/) and, by extension, its Kibana plugin. It uses the [Open ID Connect](https://en.wikipedia.org/wiki/OpenID_Connect) (OIDC) protocol on [Google's Identity Platform](https://developers.google.com/identity/protocols/OpenIDConnect).

## Prerequisites

Before doing anything, you will need to install following command line tools.
* [Terraform](https://www.terraform.io/)
* [AWS CLI](https://aws.amazon.com/cli/)

Then, you must define an environment for deploying into your AWS account. There is an environment template in `environment_template`.

```bash
cp config/environment_template environment
vim environment
```

Then, load the environment.

```bash
source environment
```

The OIDC proxy requires a load balancer to allow connections from the public internet. This infrastructure should already be created, but if it isn't you can run the following command.

```bash
# to see what changes will be made
./infrastructure.sh plan

# to apply changes
./infrastructure.sh apply
```

Note the security group id and target group ARN resulting from this function and modify the makefile accordingly.

Having adjusted these variables, if the service has not already been created you must run the command below.
```bash
make service
```

## Deployment pipeline

### Build

`elk-oidc-proxy` is deployed in Amazon ECS from a Docker container. To build this container run the command below.

```bash
$ make image
```

### Publish

You must first log into AWS Elastic Container Registry before publishing the container.

```bash
$ aws ecr get-login --no-include-email --region us-east-1
```

Then publish the container to ECR.

```bash
$ make publish
```

### Deployment

```bash
make deploy
```

### Scaling down

```bash
make scale-down
```

## Known issues

The [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) functionality used by the proxy issues temporary security credentials that only last one hour. After an hour expires, you will have to refresh the page to continue using the service.
