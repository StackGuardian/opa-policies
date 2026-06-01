resource "aws_s3_bucket" "this" {
  bucket = "very-random-name"
  
}

resource "aws_s3_bucket" "central_access_logs" {
  bucket = "bpost-aws-s3-access-logs"
}

# Fix: Explicitly log the log bucket's own data plane actions
resource "aws_s3_bucket_logging" "central_access_logs_logging" {
  bucket        = aws_s3_bucket.central_access_logs.id
  target_bucket = aws_s3_bucket.central_access_logs.id
  target_prefix = "self-logging/"
}

resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.this.id
  target_bucket = aws_s3_bucket.central_access_logs.id
  target_prefix = "${aws_s3_bucket.this.id}/"
}
