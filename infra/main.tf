# Infrastructure for HelpDeskAI: KB and attachment storage, the orders database,
# the tickets/tenant-config tables, and the ECS task role.
#
# Credentials are never declared here — the provider resolves them from the
# environment or an assumed role (OIDC in CI). State lives in an encrypted,
# versioned S3 backend.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket       = "helpdeskai-terraform-state"
    key          = "infra/main.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "vpc_id" {
  description = "VPC hosting the ECS tasks and the orders database."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the orders database subnet group."
  type        = list(string)
}

variable "orders_db_secret_arn" {
  description = "Secrets Manager secret holding the orders database credentials."
  type        = string
}

data "aws_secretsmanager_secret_version" "orders_db" {
  secret_id = var.orders_db_secret_arn
}

# ─────────────────────────────────────────────────────────────────────────────
# Knowledge-base bucket
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_kms_key" "kb_docs" {
  description             = "CMK for HelpDeskAI knowledge base documents"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "kb_docs" {
  name          = "alias/helpdeskai-kb-docs"
  target_key_id = aws_kms_key.kb_docs.key_id
}

resource "aws_s3_bucket" "kb_docs" {
  bucket = "helpdeskai-kb-docs"
}

resource "aws_s3_bucket_acl" "kb_docs" {
  bucket = aws_s3_bucket.kb_docs.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "kb_docs" {
  bucket                  = aws_s3_bucket.kb_docs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kb_docs" {
  bucket = aws_s3_bucket.kb_docs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.kb_docs.arn
    }
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# Attachments bucket
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_kms_key" "attachments" {
  description             = "CMK for HelpDeskAI customer attachments"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_s3_bucket" "attachments" {
  bucket = "helpdeskai-attachments"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "attachments" {
  bucket = aws_s3_bucket.attachments.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.attachments.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "attachments" {
  bucket                  = aws_s3_bucket.attachments.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─────────────────────────────────────────────────────────────────────────────
# DynamoDB + RDS data stores
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_kms_key" "tables" {
  description             = "CMK for HelpDeskAI DynamoDB tables"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_dynamodb_table" "tickets" {
  name         = "helpdeskAI-tickets"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tenant_id"
  range_key    = "ticket_id"

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.tables.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  attribute {
    name = "tenant_id"
    type = "S"
  }
  attribute {
    name = "ticket_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "tenant_config" {
  name         = "helpdeskAI-tenant-config"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tenant_id"

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.tables.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  attribute {
    name = "tenant_id"
    type = "S"
  }
}

resource "aws_kms_key" "orders" {
  description             = "CMK for the HelpDeskAI orders database"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "orders" {
  name          = "alias/helpdeskai-orders"
  target_key_id = aws_kms_key.orders.key_id
}

resource "aws_security_group" "app" {
  name        = "helpdeskai-app"
  description = "ECS tasks running the HelpDeskAI service"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "orders_db" {
  name        = "helpdeskai-orders-db"
  description = "Orders database; reachable only from the application tasks"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "orders_db_from_app" {
  security_group_id            = aws_security_group.orders_db.id
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_db_subnet_group" "orders" {
  name       = "helpdeskai-orders"
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_instance" "orders" {
  identifier             = "helpdeskai-orders"
  engine                 = "postgres"
  instance_class         = "db.t3.medium"
  allocated_storage      = 50
  username               = jsondecode(data.aws_secretsmanager_secret_version.orders_db.secret_string)["username"]
  password               = jsondecode(data.aws_secretsmanager_secret_version.orders_db.secret_string)["password"]
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.orders.arn
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.orders.name
  vpc_security_group_ids = [aws_security_group.orders_db.id]
  backup_retention_period = 7
  skip_final_snapshot     = false
  final_snapshot_identifier = "helpdeskai-orders-final"
}

# ─────────────────────────────────────────────────────────────────────────────
# Application logs
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_kms_key" "logs" {
  description             = "CMK for HelpDeskAI CloudWatch log groups"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/helpdeskai/app"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn
}

# ─────────────────────────────────────────────────────────────────────────────
# IAM role for the application
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "app" {
  name = "helpdeskai-app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "app" {
  name = "helpdeskai-app-policy"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject"]
        Resource = [
          "${aws_s3_bucket.kb_docs.arn}/*",
          "${aws_s3_bucket.attachments.arn}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.kb_docs.arn, aws_s3_bucket.attachments.arn]
      },
      {
        Effect = "Allow"
        Action = ["dynamodb:Query", "dynamodb:PutItem", "dynamodb:GetItem"]
        Resource = [
          aws_dynamodb_table.tickets.arn,
          aws_dynamodb_table.tenant_config.arn,
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.orders_db_secret_arn]
      },
      {
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [
          aws_kms_key.kb_docs.arn,
          aws_kms_key.attachments.arn,
          aws_kms_key.tables.arn,
          aws_kms_key.orders.arn,
        ]
      },
    ]
  })
}
