#!/bin/bash

# Run cyhy-archive script, copy resulting archive files to an AWS S3 bucket,
# then delete the archive files from the local archive directory

# set -o verbose

if [ $# -ne 3 ]
	then
		echo "Usage: $0 archive-dir s3-bucket-name s3-bucket-region"
		echo "  archive-dir        Directory to create archive files in"
		echo "  s3-bucket-name     AWS S3 bucket to copy archive files to"
		echo "  s3-bucket-region   Region of AWS S3 bucket to copy archive files to"
		exit
fi

ARCHIVE_DIR=$1
S3_BUCKET_NAME=$2
S3_BUCKET_REGION=$3

# Run cyhy-archive script
echo "Starting cyhy-archive script, creating archives in ${ARCHIVE_DIR}..."
/usr/local/bin/cyhy-archive ${ARCHIVE_DIR}

RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "ERROR: cyhy-archive failed - exiting!"
	exit $RESULT
fi
echo "Successfully executed cyhy-archive script"

# Set default AWS signature version; required in order to successfully copy
# objects to a bucket
aws configure set default.s3.signature_version s3v4

# Copy archives from ARCHIVE_DIR to S3_BUCKET_NAME
echo "Starting copy of archives to s3://${S3_BUCKET_NAME} (${S3_BUCKET_REGION})..."
aws s3 cp ${ARCHIVE_DIR}/ s3://${S3_BUCKET_NAME}/ --region ${S3_BUCKET_REGION} --recursive --exclude "*" --include "cyhy_archive*.gz"

RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "ERROR: Copy of archives to s3://${S3_BUCKET_NAME} failed - exiting!"
	exit $RESULT
fi
echo "Successfully copied archives to S3"

# Delete archives from ARCHIVE_DIR
echo "Starting delete of archives from ${ARCHIVE_DIR}..."
rm ${ARCHIVE_DIR}/cyhy_archive*.gz

RESULT=$?
if [ $RESULT -ne 0 ]; then
  echo "ERROR: Delete of archives from ${ARCHIVE_DIR} failed - exiting!"
	exit $RESULT
fi
echo "Successfully deleted archives in ${ARCHIVE_DIR}"
echo "Done!"
