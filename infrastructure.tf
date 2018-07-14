variable "aws_profile" {}

variable "aws_region" {
  default = "us-east-1"
}

variable "app_name" {
  default = "elk-oidc-proxy"
}

provider "aws" {
  region = "${var.aws_region}"
  profile = "${var.aws_profile}"
}


terraform {
  backend "s3" {
    key = "elk-oidc-proxy/terraform.tfstate"
  }
}

variable "domain_name" {}
variable "proxy_fqdn" {}
variable "cluster" {}
variable "port" {}


////
// ECR repo
//

resource "aws_ecr_repository" "logs" {
  name = "${var.app_name}"
}

resource "aws_ecr_repository_policy" "logs" {
  repository = "${aws_ecr_repository.logs.name}"
  policy = <<EOF
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "ecr:ListImages",
                "ecr:DeleteRepository",
                "ecr:BatchDeleteImage",
                "ecr:SetRepositoryPolicy",
                "ecr:DeleteRepositoryPolicy"
            ]
        }
    ]
}
EOF
}

////
// cluster
//

resource "aws_vpc" "logs" {
  cidr_block = "172.50.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.logs.id}"

  tags {
    Name = "${var.app_name}"
  }
}

resource "aws_route" "internet_access" {
  route_table_id = "${aws_vpc.logs.main_route_table_id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = "${aws_internet_gateway.gw.id}"
}

resource "aws_eip" "tuto_eip" {
  vpc      = true
  depends_on = [
    "aws_internet_gateway.gw"
  ]
}

resource "aws_subnet" "proxy_subnet0" {
  vpc_id            = "${aws_vpc.logs.id}"
  availability_zone = "${var.aws_region}a"
  cidr_block        = "${cidrsubnet(aws_vpc.logs.cidr_block, 8, 1)}"
  depends_on = [
    "aws_vpc.logs"
  ]
}

resource "aws_subnet" "proxy_subnet1" {
  vpc_id            = "${aws_vpc.logs.id}"
  availability_zone = "${var.aws_region}b"
  cidr_block        = "${cidrsubnet(aws_vpc.logs.cidr_block, 8, 2)}"
  depends_on = [
    "aws_vpc.logs"
  ]
}

resource "aws_route_table" "private_route_table" {
  vpc_id = "${aws_vpc.logs.id}"
  tags {
      Name = "Private route table"
  }
}

//nat_gateway_id = "${aws_nat_gateway.nat.id}"
resource "aws_route" "private_route" {
  route_table_id  = "${aws_route_table.private_route_table.id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = "${aws_internet_gateway.gw.id}"
}

resource "aws_route_table_association" "subnet0" {
  subnet_id = "${aws_subnet.proxy_subnet0.id}"
  route_table_id = "${aws_route_table.private_route_table.id}"
}

resource "aws_route_table_association" "subnet1" {
  subnet_id = "${aws_subnet.proxy_subnet1.id}"
  route_table_id = "${aws_route_table.private_route_table.id}"
}

data "aws_subnet_ids" "default" {
  vpc_id = "${aws_vpc.logs.id}"
  depends_on = [
    "aws_subnet.proxy_subnet0",
    "aws_subnet.proxy_subnet1"
  ]
}

resource "aws_ecs_cluster" "fargate" {
  name = "${var.cluster}"
}

output "subnets" {
  value = ["${data.aws_subnet_ids.default.ids}"]
}



////
// DNS
//

resource "aws_route53_record" "proxy" {
  zone_id = "${data.aws_route53_zone.primary.zone_id}"
  name = "${var.proxy_fqdn}"
  type = "A"
  alias {
    evaluate_target_health = true
    name = "${aws_lb.proxy.dns_name}"
    zone_id = "${aws_lb.proxy.zone_id}"
  }
}

resource "aws_acm_certificate" "cert" {
  domain_name = "${aws_route53_record.proxy.name}"
  validation_method = "DNS"
}

data "aws_route53_zone" "primary" {
  name         = "${var.domain_name}."
  private_zone = false
}

resource "aws_route53_record" "cert_validation" {
  name = "${aws_acm_certificate.cert.domain_validation_options.0.resource_record_name}"
  type = "${aws_acm_certificate.cert.domain_validation_options.0.resource_record_type}"
  zone_id = "${data.aws_route53_zone.primary.id}"
  records = ["${aws_acm_certificate.cert.domain_validation_options.0.resource_record_value}"]
  ttl = 60
}

resource "aws_acm_certificate_validation" "cert" {
  certificate_arn = "${aws_acm_certificate.cert.arn}"
  validation_record_fqdns = ["${aws_route53_record.cert_validation.fqdn}"]
}

////
// load balancer
//

resource "aws_security_group" "proxy" {
  name = "${var.app_name}"
  vpc_id = "${aws_vpc.logs.id}"
}

resource "aws_security_group_rule" "proxy_http" {
  type = "ingress"
  from_port = 80
  to_port = 80
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = "${aws_security_group.proxy.id}"
}

resource "aws_security_group_rule" "proxy_https" {
  type = "ingress"
  from_port = 443
  to_port = 443
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = "${aws_security_group.proxy.id}"
}

resource "aws_security_group_rule" "outbound" {
  type = "egress"
  from_port = 0
  to_port = 65535
  protocol = "all"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = "${aws_security_group.proxy.id}"
}

resource "aws_lb" "proxy" {
  name = "${var.app_name}"
  subnets = ["${data.aws_subnet_ids.default.ids}"]
  security_groups = ["${aws_security_group.proxy.id}"]
  depends_on = [
    "aws_internet_gateway.gw"
  ]
}

resource "aws_lb_target_group" "proxy" {
  name = "${var.app_name}"
  protocol = "HTTP"
  port = 80
  vpc_id = "${aws_vpc.logs.id}"
  target_type = "ip"
  health_check {
    protocol = "HTTP"
    port = 80
    path = "/-/health"
    matcher = "200"
  }
}

resource "aws_lb_listener" "proxy_http" {
  load_balancer_arn = "${aws_lb.proxy.arn}"
  protocol = "HTTP"
  port = 80
  default_action {
    target_group_arn = "${aws_lb_target_group.proxy.arn}"
    type = "forward"
  }
}

resource "aws_lb_listener" "proxy_https" {
  load_balancer_arn = "${aws_lb.proxy.arn}"
  protocol = "HTTPS"
  port = 443
  certificate_arn = "${aws_acm_certificate_validation.cert.certificate_arn}"
  default_action {
    target_group_arn = "${aws_lb_target_group.proxy.arn}"
    type = "forward"
  }
}

output "security_group" {
  value = "${aws_security_group.proxy.id}"
}


////
// app deployment
//

data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_log_group" "ecs" {
  name = "/aws/ecs/${var.app_name}"
  retention_in_days = "90"
}


// task executor role
resource "aws_iam_role" "task_executor" {
  name = "elkProxyEcsTaskExecutionRole"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "ecs.amazonaws.com",
          "ecs-tasks.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "logs_writer" {
  name = "LogsWriter"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ecs/elk-oidc-proxy:*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "task_executor_logs" {
  policy_arn = "${aws_iam_policy.logs_writer.arn}"
  role = "${aws_iam_role.task_executor.name}"
}

resource "aws_iam_role_policy_attachment" "task_executor_ecs" {
  role = "${aws_iam_role.task_executor.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "task_executor_ecr" {
  role = "${aws_iam_role.task_executor.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

// task role
resource "aws_iam_role" "proxy" {
  name = "${var.app_name}"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "ecs-tasks.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}


resource "aws_iam_role_policy" "proxy" {
  name = "${var.app_name}"
  role = "${aws_iam_role.proxy.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.app_name}",
            "Effect": "Allow"
        }
    ]
}
EOF
}

output "task_definition" {
  value = <<EOF
{
  "family": "${var.app_name}",
  "containerDefinitions": [
      {
          "name": "${var.app_name}",
          "image": "${aws_ecr_repository.logs.repository_url}",
          "cpu": 0,
          "memoryReservation": 512,
          "portMappings": [
              {
                  "containerPort": 80,
                  "hostPort": 80,
                  "protocol": "tcp"
              },
              {
                  "containerPort": 443,
                  "hostPort": 443,
                  "protocol": "tcp"
              }
          ],
          "essential": true,
          "environment": [
              {
                  "name": "PORT",
                  "value": "${var.port}"
              }
          ],
          "mountPoints": [],
          "volumesFrom": [],
          "logConfiguration": {
              "logDriver": "awslogs",
              "options": {
                  "awslogs-group": "/aws/ecs/${var.app_name}",
                  "awslogs-region": "${var.aws_region}",
                  "awslogs-stream-prefix": "ecs"
              }
          }
      }
  ],
  "taskRoleArn": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.app_name}",
  "executionRoleArn": "${aws_iam_role.task_executor.arn}",
  "networkMode": "awsvpc",
  "volumes": [],
  "placementConstraints": [],
  "requiresCompatibilities": [
      "FARGATE"
  ],
  "cpu": "512",
  "memory": "1024"
}
EOF
}
