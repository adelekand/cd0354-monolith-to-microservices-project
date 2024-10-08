import AWS = require("aws-sdk");
import { config } from "./config/config";

// Configure AWS
AWS.config.update({
  region: config.aws_region,
});

export const s3 = new AWS.S3({
  signatureVersion: "v4",
  accessKeyId: config.aws_access_key_id,
  secretAccessKey: config.aws_access_key,
});

// Generates an AWS signed URL for retrieving objects
export function getGetSignedUrl(key: string): string {
  const signedUrlExpireSeconds = 60 * 5;

  return s3.getSignedUrl("getObject", {
    Bucket: config.aws_media_bucket,
    Key: key,
    Expires: signedUrlExpireSeconds,
  });
}

// Generates an AWS signed URL for uploading objects
export function getPutSignedUrl(key: string): string {
  const signedUrlExpireSeconds = 60 * 5;

  return s3.getSignedUrl("putObject", {
    Bucket: config.aws_media_bucket,
    Key: key,
    Expires: signedUrlExpireSeconds,
  });
}
