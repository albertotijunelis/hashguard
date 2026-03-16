# HashGuard SaaS — Terraform Infrastructure (AWS ECS Fargate)
#
# Usage:
#   cd infra/
#   terraform init
#   terraform plan -var-file=prod.tfvars
#   terraform apply -var-file=prod.tfvars

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket = "hashguard-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ───────────────────────────────────────────────────────────────

variable "aws_region" {
  default = "us-east-1"
}

variable "environment" {
  default = "production"
}

variable "domain" {
  default = "hashguard.org"
}

variable "db_password" {
  sensitive = true
}

variable "image_tag" {
  default = "latest"
}

variable "stripe_secret_key" {
  sensitive = true
}

variable "smtp_pass" {
  sensitive = true
}

variable "secret_key" {
  sensitive = true
}

# ── VPC ─────────────────────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "hashguard-${var.environment}" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "hashguard-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "hashguard-private-${count.index + 1}" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "hashguard-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "hashguard-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "hashguard-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "hashguard-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "hashguard-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ── Security Groups ────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name_prefix = "hashguard-alb-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "hashguard-alb-sg" }
}

resource "aws_security_group" "ecs" {
  name_prefix = "hashguard-ecs-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "hashguard-ecs-sg" }
}

resource "aws_security_group" "db" {
  name_prefix = "hashguard-db-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  tags = { Name = "hashguard-db-sg" }
}

resource "aws_security_group" "redis" {
  name_prefix = "hashguard-redis-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  tags = { Name = "hashguard-redis-sg" }
}

# ── RDS PostgreSQL ──────────────────────────────────────────────────────────

resource "aws_db_subnet_group" "main" {
  name       = "hashguard-${var.environment}"
  subnet_ids = aws_subnet.private[*].id
  tags       = { Name = "hashguard-db-subnet" }
}

resource "aws_db_instance" "main" {
  identifier     = "hashguard-${var.environment}"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = "db.t3.micro"

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_encrypted     = true

  db_name  = "hashguard"
  username = "hashguard"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]

  backup_retention_period = 7
  skip_final_snapshot     = false
  final_snapshot_identifier = "hashguard-final-${var.environment}"
  deletion_protection     = true

  tags = { Name = "hashguard-db" }
}

# ── ElastiCache Redis ───────────────────────────────────────────────────────

resource "aws_elasticache_subnet_group" "main" {
  name       = "hashguard-${var.environment}"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_cluster" "main" {
  cluster_id           = "hashguard-${var.environment}"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  subnet_group_name    = aws_elasticache_subnet_group.main.name
  security_group_ids   = [aws_security_group.redis.id]

  tags = { Name = "hashguard-redis" }
}

# ── ALB ─────────────────────────────────────────────────────────────────────

resource "aws_lb" "main" {
  name               = "hashguard-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = { Name = "hashguard-alb" }
}

resource "aws_lb_target_group" "api" {
  name        = "hashguard-api-${var.environment}"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/api/stats"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 10
  }

  tags = { Name = "hashguard-api-tg" }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.main.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ── ACM Certificate ────────────────────────────────────────────────────────

resource "aws_acm_certificate" "main" {
  domain_name               = var.domain
  subject_alternative_names = ["*.${var.domain}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "hashguard-cert" }
}

resource "aws_acm_certificate_validation" "main" {
  certificate_arn = aws_acm_certificate.main.arn
}

# ── ECS Cluster ─────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "main" {
  name = "hashguard-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = "hashguard-cluster" }
}

# ── ECS Task Definition ────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "api" {
  family                   = "hashguard-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = "ghcr.io/hashguard/hashguard:${var.image_tag}"
      essential = true

      portMappings = [{
        containerPort = 8000
        protocol      = "tcp"
      }]

      environment = [
        { name = "DATABASE_URL", value = "postgresql://hashguard:${var.db_password}@${aws_db_instance.main.endpoint}/hashguard" },
        { name = "CELERY_BROKER_URL", value = "redis://${aws_elasticache_cluster.main.cache_nodes[0].address}:6379/0" },
        { name = "CELERY_RESULT_BACKEND", value = "redis://${aws_elasticache_cluster.main.cache_nodes[0].address}:6379/0" },
        { name = "HASHGUARD_AUTH", value = "1" },
        { name = "HASHGUARD_ENV", value = "production" },
        { name = "HASHGUARD_URL", value = "https://${var.domain}" },
        { name = "SMTP_HOST", value = "smtp.resend.com" },
        { name = "SMTP_PORT", value = "465" },
        { name = "SMTP_USER", value = "resend" },
        { name = "SMTP_FROM", value = "noreply@${var.domain}" },
      ]

      secrets = [
        { name = "STRIPE_SECRET_KEY", valueFrom = "${aws_ssm_parameter.stripe_key.arn}" },
        { name = "SMTP_PASS", valueFrom = "${aws_ssm_parameter.smtp_pass.arn}" },
        { name = "HASHGUARD_SECRET_KEY", valueFrom = "${aws_ssm_parameter.secret_key.arn}" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "api"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/api/stats')\" || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = { Name = "hashguard-api-task" }
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "hashguard-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "worker"
      image     = "ghcr.io/hashguard/hashguard:${var.image_tag}"
      essential = true
      command   = ["celery", "-A", "hashguard.tasks", "worker", "--loglevel=info", "--concurrency=2"]

      environment = [
        { name = "DATABASE_URL", value = "postgresql://hashguard:${var.db_password}@${aws_db_instance.main.endpoint}/hashguard" },
        { name = "CELERY_BROKER_URL", value = "redis://${aws_elasticache_cluster.main.cache_nodes[0].address}:6379/0" },
        { name = "CELERY_RESULT_BACKEND", value = "redis://${aws_elasticache_cluster.main.cache_nodes[0].address}:6379/0" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "worker"
        }
      }
    }
  ])

  tags = { Name = "hashguard-worker-task" }
}

# ── ECS Services ────────────────────────────────────────────────────────────

resource "aws_ecs_service" "api" {
  name            = "hashguard-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }

  depends_on = [aws_lb_listener.https]

  tags = { Name = "hashguard-api-svc" }
}

resource "aws_ecs_service" "worker" {
  name            = "hashguard-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs.id]
  }

  tags = { Name = "hashguard-worker-svc" }
}

# ── Auto Scaling ────────────────────────────────────────────────────────────

resource "aws_appautoscaling_target" "api" {
  max_capacity       = 10
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "api_cpu" {
  name               = "hashguard-api-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# ── IAM Roles ───────────────────────────────────────────────────────────────

resource "aws_iam_role" "ecs_execution" {
  name = "hashguard-ecs-execution-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_ssm" {
  name = "ssm-access"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameters", "ssm:GetParameter"]
      Resource = "arn:aws:ssm:${var.aws_region}:*:parameter/hashguard/*"
    }]
  })
}

resource "aws_iam_role" "ecs_task" {
  name = "hashguard-ecs-task-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

# ── SSM Parameters (Secrets) ───────────────────────────────────────────────

resource "aws_ssm_parameter" "stripe_key" {
  name  = "/hashguard/stripe-secret-key"
  type  = "SecureString"
  value = var.stripe_secret_key
}

resource "aws_ssm_parameter" "smtp_pass" {
  name  = "/hashguard/smtp-pass"
  type  = "SecureString"
  value = var.smtp_pass
}

resource "aws_ssm_parameter" "secret_key" {
  name  = "/hashguard/secret-key"
  type  = "SecureString"
  value = var.secret_key
}

# ── CloudWatch Logs ─────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/hashguard-${var.environment}"
  retention_in_days = 30

  tags = { Name = "hashguard-logs" }
}

# ── Outputs ─────────────────────────────────────────────────────────────────

output "alb_dns" {
  value = aws_lb.main.dns_name
}

output "db_endpoint" {
  value = aws_db_instance.main.endpoint
}

output "redis_endpoint" {
  value = aws_elasticache_cluster.main.cache_nodes[0].address
}

output "ecs_cluster" {
  value = aws_ecs_cluster.main.name
}
