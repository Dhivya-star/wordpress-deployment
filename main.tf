terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region  = "eu-west-1"
}

# Create a VPC
resource "aws_vpc" "VPC-01" {
  cidr_block       = "192.168.0.0/16"
  instance_tenancy = "default"
  enable_dns_support   = true    # ✅ Enables DNS resolution
  enable_dns_hostnames = true    # ✅ Enables public DNS names

  tags = {
    Name = "VPC-01"
  }
}

# Create and attach IGW to VPC-01
resource "aws_internet_gateway" "IGW-01" {
  vpc_id = aws_vpc.VPC-01.id

  tags = {
    Name = "IGW-01"
  }
}

# Create Public subnet 
resource "aws_subnet" "public-SN" {
  vpc_id     = aws_vpc.VPC-01.id
  cidr_block = "192.168.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-SN"
  }
}

# Create Private Subnet in AZ1
resource "aws_subnet" "private-SN-az1" {
  vpc_id            = aws_vpc.VPC-01.id
  cidr_block        = "192.168.2.0/24"
  availability_zone = "eu-west-1a"

  tags = {
    Name = "Private Subnet AZ1"
  }
}

# Create Private Subnet in AZ2
resource "aws_subnet" "private-SN-az2" {
  vpc_id            = aws_vpc.VPC-01.id
  cidr_block        = "192.168.3.0/24"
  availability_zone = "eu-west-1b"

  tags = {
    Name = "Private Subnet AZ2"
  }
}

# Create a public RT
resource "aws_route_table" "VPC-01-public-RT" {
  vpc_id = aws_vpc.VPC-01.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.IGW-01.id
  }

  tags = {
    Name = "VPC-01-public-RT"
  }
}

# Public subnet association with public RT
resource "aws_route_table_association" "VPC-01-public-RT-Association" {
  subnet_id      = aws_subnet.public-SN.id
  route_table_id = aws_route_table.VPC-01-public-RT.id
}

# Create an Elastic IP
resource "aws_eip" "Nat-EIP" {
  domain   = "vpc"

  tags = {
    Name = "Nat-EIP"
  }
}

# Create a NAT gateway
resource "aws_nat_gateway" "NAT-gateway" {
  allocation_id = aws_eip.Nat-EIP.id
  subnet_id     = aws_subnet.public-SN.id

  tags = {
    Name = "NAT-gateway"
  }
}

# Create a private RT
resource "aws_route_table" "VPC-01-private-RT" {
  vpc_id = aws_vpc.VPC-01.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.NAT-gateway.id
  }

  tags = {
    Name = "VPC-01-private-RT"
  }
}

# Associate Private Subnet in AZ1 with Private Route Table
resource "aws_route_table_association" "private-RT-Association-az1" {
  subnet_id      = aws_subnet.private-SN-az1.id
  route_table_id = aws_route_table.VPC-01-private-RT.id
}

# Associate Private Subnet in AZ2 with Private Route Table
resource "aws_route_table_association" "private-RT-Association-az2" {
  subnet_id      = aws_subnet.private-SN-az2.id
  route_table_id = aws_route_table.VPC-01-private-RT.id
}

# create a security group for public instance
resource "aws_security_group" "VPC-01-VM-NSG" {
  name        = "allow_tls"
  description = "Allow SSH,HTTP and mysql access"
  vpc_id      = aws_vpc.VPC-01.id

  tags = {
    Name = "VPC-01-VM-NSG"
  }
}

resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv4" {
  security_group_id = aws_security_group.VPC-01-VM-NSG.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
}

resource "aws_vpc_security_group_ingress_rule" "allow_HTTP_access" {  # Missing port 22 ssh rule above this
  security_group_id = aws_security_group.VPC-01-VM-NSG.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
}

resource "aws_vpc_security_group_ingress_rule" "allow_mysql_access" {
  security_group_id = aws_security_group.VPC-01-VM-NSG.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 3306
  ip_protocol       = "tcp"
  to_port           = 3306
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.VPC-01-VM-NSG.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

# Create an IAM Role
resource "aws_iam_role" "test_role1" {
  name = "test_role1"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    tag-key = "test_role1"
  }
}

# Create an EC2-instance profile
resource "aws_iam_instance_profile" "test_profile1" {
  name = "test_profile1"
  role = aws_iam_role.test_role1.name
}

# create an iam_policy
resource "aws_iam_policy" "test_policy1" {
  name = "test_policy1"
  description = "IAM policy for Terraform execution role"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:*",
          "vpc:*",
          "iam:*",
          "rds:*",
          "secretsmanager:GetSecretValue",  # Allow reading secrets
          "secretsmanager:ListSecrets",    # Allow listing secrets
          "secretsmanager:DescribeSecret",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

#Attaching IAM policy with IAM role
resource "aws_iam_role_policy_attachment" "test_role_policy_attach" {
  role       = aws_iam_role.test_role1.name
  policy_arn = aws_iam_policy.test_policy1.arn
}

#Create a public instance
resource "aws_instance" "Public-VM" {
  ami                         	=  "ami-0b5a7998795f497af"   # This is for amzon linux2 ami (eu-west-1)
  instance_type               	=  "t2.micro"  
  subnet_id                  	  =  aws_subnet.public-SN.id
  key_name                    	=  "server-key"
  vpc_security_group_ids      	=  [aws_security_group.VPC-01-VM-NSG.id]
  iam_instance_profile          = "${aws_iam_instance_profile.test_profile1.name}"
  associate_public_ip_address 	=  true

# Terraform will create the inventory.ini file automatically
  provisioner "local-exec" {
    command = <<EOT
      mkdir -p /var/lib/jenkins/workspace/Terraform-Ansible-Pipeline/
      echo "[webservers]" > /var/lib/jenkins/workspace/Terraform-Ansible-Pipeline/inventory.ini
      echo "${self.public_ip} ansible_user=ec2-user ansible_ssh_private_key_file=/home/ec2-user/server-key.pem" >> /var/lib/jenkins/workspace/Terraform-Ansible-Pipeline/inventory.ini
    EOT
  }

# User data for setting up SSH keys
  user_data = <<-EOF
    #!/bin/bash
    mkdir -p /home/ec2-user/.ssh
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDREyIwbOurGqimpZNArcPfAdNZ3bC9U1SUdLIdTry5dcfCnYRP/uG8qE1nWuYZMy/eUbmXr6nUib8vERwp6cqjz9/EgUHlyPBRlCsUEZXAQ+W38Z/hS4uWOdTSTz5jEGoQpUv79xakr68Eonpk4DtL57ELZMEC2hOYBZy7HAqbnQOlyK+VqeSKzzkcveD8PnreQMwTAFDsAV1ZFFPuR0/ixbsSf6qLLqD5uVeKaNv3eQFixDQcdsCr2B6WGL2hxkucWofFwxj4FTaNALaHJ/tBwJ1g5NuqKSwTdGg2gDwGa7REnqa8V5jNpj6XAetQwDMavBGytAD6LJxvBKiAtZgV/xScg0wbWz33rqOL7Y3Rnd4u8BB9lBz/cTRErs4mFq9UK6U+iDme5kDWEEXJobVo5DIUHqqfz0l2N3EJpk26TUO0NXyPmX0odBH/f6wc008iGgnlu+ZhhqS5NsH+LctlfZvN7IgHQXWZp2D59BhnJqrrBOjkm1sEm4kj8iW0aDRGvDp17IB/YzK+4zAeUO4/LNJJW2jaHlVQ2CgUKS578XoA5RzpuJlvVfv+Vf1uJl8nIMfp8WOyYT3HStOGNO/lhEIXmasxpjfeflcZN8DPnKYv+ey2fKizrtb2sD8RgGGtyCpiBm1GlHI5ue3FSTBMX8cMInpL1fOnmLmwSRrohQ== ec2-user@ip-172-31-0-29.eu-west-1.compute.internal" > /home/ec2-user/.ssh/authorized_keys
    chmod 600 /home/ec2-user/.ssh/authorized_keys
    chown ec2-user:ec2-user /home/ec2-user/.ssh/authorized_keys
  EOF

  tags = {
    Name = "Public-VM"
  }
}

# Create a security group for Amazon RDS database

resource "aws_security_group" "RDS-NSG" {
  name        = "RDS Security Group"
  description = "Allow MySQL access from app instances"
  vpc_id      = aws_vpc.VPC-01.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.VPC-01-VM-NSG.id] # Allow only app servers
  }
  tags = {
    Name = "RDS-NSG"
  }
}

# Create a subnet group for RDS
resource "aws_db_subnet_group" "my_db_subnet_group" {
  name       = "my-db-subnet-group"
  subnet_ids = [aws_subnet.private-SN-az1.id, aws_subnet.private-SN-az2.id]

  tags = {
    Name = "My DB Subnet Group"
  }
}

# To create a new secret using secrets manager
resource "aws_secretsmanager_secret" "rds_secret" {
  name = "rds-db-credentials"
  description = "RDS MySQL Database credentials"
  kms_key_id  = "alias/aws/secretsmanager"
}

resource "aws_secretsmanager_secret_version" "rds_secret_version" {
  secret_id     = aws_secretsmanager_secret.rds_secret.id
  secret_string = jsonencode({
    username = "admin"
    password = "wordpress"
  })
}

# To create an AWS DB instance
resource "aws_db_instance" "RDS-db-Instance" {
  engine                 = "mysql"
  engine_version         = "5.7"
  db_name                = "wordpressdb"
  identifier             = "wordpressdb"
  instance_class         = "db.t3.small"
  allocated_storage      = 20
  publicly_accessible    = false
  username               = jsondecode(aws_secretsmanager_secret_version.rds_secret_version.secret_string)["username"]
  password               = jsondecode(aws_secretsmanager_secret_version.rds_secret_version.secret_string)["password"]
  vpc_security_group_ids = [aws_security_group.RDS-NSG.id]
  db_subnet_group_name   = aws_db_subnet_group.my_db_subnet_group.name
  skip_final_snapshot    = true
  multi_az               = true # Enable for production

  tags = {
    Name = "RDS-db-Instance"
  }
}


