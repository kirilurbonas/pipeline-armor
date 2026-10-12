# DELIBERATELY INSECURE — scanner canary for scanner-canary.yml, never apply.
# World-open SSH and a public-read bucket must keep producing IaC findings.

resource "aws_security_group" "open" {
  name        = "open"
  description = "open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "b" {
  bucket = "b"
  acl    = "public-read"
}
