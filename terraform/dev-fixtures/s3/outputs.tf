output "private_good_bucket_name" {
  value = aws_s3_bucket.private_good.bucket
}

output "pab_disabled_bad_bucket_name" {
  value = aws_s3_bucket.pab_disabled_bad.bucket
}