/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package s3sessions

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/session"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// Config is handler configuration
type Config struct {
	// Bucket is S3 bucket name
	Bucket string
	// Region is S3 bucket region
	Region string
	// Path is an optional bucket path
	Path string
	// Session is an optional existing AWS client session
	Session *awssession.Session
}

// CheckAndSetDefaults checks and sets defaults
func (s *Config) CheckAndSetDefaults() error {
	if s.Bucket == "" {
		return trace.BadParameter("missing parameter Bucket")
	}
	if s.Session == nil {
		// create an AWS session using default SDK behavior, i.e. it will interpret
		// the environment and ~/.aws directory just like an AWS CLI tool would:
		sess, err := awssession.NewSessionWithOptions(awssession.Options{
			SharedConfigState: awssession.SharedConfigEnable,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		// override the default environment (region + credentials) with the values
		// from the YAML file:
		if s.Region != "" {
			sess.Config.Region = aws.String(s.Region)
		}
		s.Session = sess
	}
	return nil
}

// NewHandler returns new S3 uploader
func NewHandler(cfg Config) (*Handler, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	h := &Handler{
		Entry: log.WithFields(log.Fields{
			trace.Component: teleport.Component(teleport.SchemeS3),
		}),
		Config:     cfg,
		uploader:   s3manager.NewUploader(cfg.Session),
		downloader: s3manager.NewDownloader(cfg.Session),
		client:     s3.New(cfg.Session),
	}
	start := time.Now()
	h.Infof("Setting up bucket %q, sessions path %q in region %q.", h.Bucket, h.Path, h.Region)
	if err := h.ensureBucket(); err != nil {
		return nil, trace.Wrap(err)
	}
	h.WithFields(log.Fields{"duration": time.Now().Sub(start)}).Infof("Setup bucket %q completed.", h.Bucket)
	return h, nil
}

// Handler handles upload and downloads to S3 object storage
type Handler struct {
	// Config is handler configuration
	Config
	// Entry is a logging entry
	*log.Entry
	uploader   *s3manager.Uploader
	downloader *s3manager.Downloader
	client     *s3.S3
}

// Closer releases connection and resources associated with log if any
func (l *Handler) Close() error {
	return nil
}

// Upload uploads object to S3 bucket, reads the contents of the object from reader
// and returns the target S3 bucket path in case of successful upload.
func (l *Handler) Upload(ctx context.Context, sessionID session.ID, reader io.Reader) (string, error) {
	path := l.path(sessionID)
	_, err := l.uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		Bucket:               aws.String(l.Bucket),
		Key:                  aws.String(path),
		Body:                 reader,
		ServerSideEncryption: aws.String(s3.ServerSideEncryptionAwsKms),
	})
	if err != nil {
		return "", ConvertS3Error(err)
	}
	return fmt.Sprintf("%v://%v/%v", teleport.SchemeS3, l.Bucket, path), nil
}

// Download downloads recorded session from S3 bucket and writes the results into writer
// return trace.NotFound error is object is not found
func (l *Handler) Download(ctx context.Context, sessionID session.ID, writer io.WriterAt) error {
	written, err := l.downloader.DownloadWithContext(ctx, writer, &s3.GetObjectInput{
		Bucket: aws.String(l.Bucket),
		Key:    aws.String(l.path(sessionID)),
	})
	if err != nil {
		return ConvertS3Error(err)
	}
	if written == 0 {
		return trace.NotFound("recording for %v is not found", sessionID)
	}
	return nil
}

// delete bucket deletes bucket and all it's contents and is used in tests
func (h *Handler) deleteBucket() error {
	// first, list and delete all the objects in the bucket
	out, err := h.client.ListObjectVersions(&s3.ListObjectVersionsInput{
		Bucket: aws.String(h.Bucket),
	})
	if err != nil {
		return ConvertS3Error(err)
	}
	for _, ver := range out.Versions {
		_, err := h.client.DeleteObject(&s3.DeleteObjectInput{
			Bucket:    aws.String(h.Bucket),
			Key:       ver.Key,
			VersionId: ver.VersionId,
		})
		if err != nil {
			return ConvertS3Error(err)
		}
	}
	_, err = h.client.DeleteBucket(&s3.DeleteBucketInput{
		Bucket: aws.String(h.Bucket),
	})
	return ConvertS3Error(err)
}

func (l *Handler) path(sessionID session.ID) string {
	if l.Path == "" {
		return string(sessionID) + ".tar"
	}
	return strings.TrimPrefix(filepath.Join(l.Path, string(sessionID)+".tar"), "/")
}

// ensureBucket makes sure bucket exists, and if it does not, creates it
func (h *Handler) ensureBucket() error {
	_, err := h.client.HeadBucket(&s3.HeadBucketInput{
		Bucket: aws.String(h.Bucket),
	})
	err = ConvertS3Error(err)
	// assumes that bucket is administered by other entity
	if err == nil {
		return nil
	}
	if !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	input := &s3.CreateBucketInput{
		Bucket: aws.String(h.Bucket),
		ACL:    aws.String("private"),
	}
	_, err = h.client.CreateBucket(input)
	err = ConvertS3Error(err, "bucket %v already exists", aws.String(h.Bucket))
	if err != nil {
		if !trace.IsAlreadyExists(err) {
			return trace.Wrap(err)
		}
		// if this client has not created the bucket, don't reconfigure it
		return nil
	}

	// Turn on versioning.
	ver := &s3.PutBucketVersioningInput{
		Bucket: aws.String(h.Bucket),
		VersioningConfiguration: &s3.VersioningConfiguration{
			Status: aws.String("Enabled"),
		},
	}
	_, err = h.client.PutBucketVersioning(ver)
	err = ConvertS3Error(err, "failed to set versioning state for bucket %q", h.Bucket)
	if err != nil {
		return trace.Wrap(err)
	}

	// Turn on server-side encryption for the bucket.
	_, err = h.client.PutBucketEncryption(&s3.PutBucketEncryptionInput{
		Bucket: aws.String(h.Bucket),
		ServerSideEncryptionConfiguration: &s3.ServerSideEncryptionConfiguration{
			Rules: []*s3.ServerSideEncryptionRule{&s3.ServerSideEncryptionRule{
				ApplyServerSideEncryptionByDefault: &s3.ServerSideEncryptionByDefault{
					SSEAlgorithm: aws.String(s3.ServerSideEncryptionAwsKms),
				},
			}},
		},
	})
	err = ConvertS3Error(err, "failed to set versioning state for bucket %q", h.Bucket)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// ConvertS3Error wraps S3 error and returns trace equivalent
func ConvertS3Error(err error, args ...interface{}) error {
	if err == nil {
		return nil
	}
	if aerr, ok := err.(awserr.Error); ok {
		switch aerr.Code() {
		case s3.ErrCodeNoSuchKey, s3.ErrCodeNoSuchBucket, s3.ErrCodeNoSuchUpload, "NotFound":
			return trace.NotFound(aerr.Error(), args...)
		case s3.ErrCodeBucketAlreadyExists, s3.ErrCodeBucketAlreadyOwnedByYou:
			return trace.AlreadyExists(aerr.Error(), args...)
		default:
			return trace.BadParameter(aerr.Error(), args...)
		}
	}
	return err
}
