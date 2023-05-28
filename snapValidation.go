package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"reflect"
	"regexp"
	"strings"
	"time"
)

type (
	SnapValidationRes struct {
		ResponseCode    string `json:"responseCode"`
		ResponseMessage string `json:"responseMessage"`
	}

	SecretRes struct {
		AccessToken string `db:"access_token" json:"accessToken"`
		ExpiredTime string `db:"expires_time" json:"expires_time"`
	}
)

func SnapFieldValueEmpty(name string) string {
	return fmt.Sprintf("Field %s is required", name)
}

func SnapFieldValueLengthIsLonger(name string, length int) string {
	return fmt.Sprintf("Field %s must be a string type with a maximum length of '%d'.", name, length)
}

func SnapFieldValueFormatInvalid(name string) string {
	return fmt.Sprintf("Invalid field format %s", name)
}

func SnapContentType(contentType string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	if reflect.DeepEqual(contentType, "") {
		res.ResponseCode = snapCode.InvalidFieldFormat
		res.ResponseMessage = SnapFieldValueEmpty("contentType")

		return res
	} else if !reflect.DeepEqual(contentType, "application/json") {
		res.ResponseCode = snapCode.MissingMandatory
		res.ResponseMessage = "Invalid mandatory field [Content-Type]"

		return res
	} else if len(contentType) > 127 {
		res.ResponseCode = snapCode.InvalidFieldFormat
		res.ResponseMessage = "Content-Type must be a string or array type with a maximum length of '127'."

		return res
	}

	return nil
}

func SnapAuthorization(token, compare string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	if _, err := packages.VerifyToken(token); err != nil {
		res.ResponseCode = snapCode.InvalidToken
		res.ResponseMessage = "Unauthorized. [Invalid Token]"

		return res
	} else if len(token) > 2048 {
		res.ResponseCode = snapCode.InvalidFieldFormat
		res.ResponseMessage = "Authorization must be a string type with a maximum length of '2048'."

		return res
	} else if token != compare {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Invalid Signature]"

		return res
	}

	return nil
}

func SnapXTimestamp(timeStamp string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	location, _ := time.LoadLocation("Asia/Jakarta")
	datenow := time.Now().In(location).Format(time.RFC3339)
	dateNowMax := time.Now().In(location).Add(time.Duration(time.Second * 900))

	if reflect.DeepEqual(timeStamp, "") {
		res.ResponseCode = snapCode.InvalidFieldFormat
		res.ResponseMessage = SnapFieldValueEmpty("timeStamp")

		return res
	} else if _, err := time.Parse(time.RFC3339, timeStamp); err != nil {
		res.ResponseCode = snapCode.MissingMandatory
		res.ResponseMessage = "Invalid mandatory field [X-TIMESTAMP]"

		return res
	}

	parseTimeStamp, _ := time.ParseInLocation(time.RFC3339, timeStamp, location)

	if len(timeStamp) > 25 {
		res.ResponseCode = snapCode.InvalidFieldFormat
		res.ResponseMessage = "Timestamp must be a string or array type with a maximum length of '25'."

		return res
	} else if timeStamp <= datenow || parseTimeStamp.Format(time.RFC3339) >= dateNowMax.Format(time.RFC3339) {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Invalid Signature]"

		return res
	}

	return nil
}

func SnapXPartnerId(partnerId, compare string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	if reflect.DeepEqual(partnerId, "") || !govalidator.IsNumeric(partnerId) {
		res.ResponseCode = snapCode.MissingMandatory
		res.ResponseMessage = "Invalid mandatory field [X-PARTNER-ID]"

		return res
	} else if len(partnerId) > 36 {
		res.ResponseCode = snapCode.InvalidFieldFormat
		res.ResponseMessage = "X-PARTNER-ID must be a string or array type with a maximum length of '36'."

		return res
	} else if partnerId != compare {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Invalid Signature]"

		return res
	}

	return nil
}

func SnapXExternalId(externalId string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	if reflect.DeepEqual(externalId, "") || !govalidator.IsNumeric(externalId) {
		res.ResponseCode = snapCode.MissingMandatory
		res.ResponseMessage = "Invalid mandatory field [X-EXTERNAL-ID]"

		return res
	} else if len(externalId) > 36 {
		res.ResponseCode = snapCode.InvalidFieldFormat
		res.ResponseMessage = "X-EXTERNAL-ID must be a string or array type with a maximum length of '36'."

		return res
	}

	return nil
}

func SnapChannelId(channelId string, compare string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	if reflect.DeepEqual(channelId, "") || !govalidator.IsNumeric(channelId) || channelId != compare {
		res.ResponseCode = snapCode.MissingMandatory
		res.ResponseMessage = "Invalid mandatory field [CHANNEL-ID]"

		return res
	} else if len(channelId) > 5 {
		res.ResponseCode = snapCode.InvalidFieldFormat
		res.ResponseMessage = "CHANNEL-ID must be a string or array type with a maximum length of '5'."

		return res
	}

	return nil
}

func SnapClientKey(clientKey, compare string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	if clientKey != compare {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Unknown Client]"

		return res
	}

	return nil
}

func SnapClientSecret(clientSecret, compare string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	if clientSecret != compare {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Unknown Client]"

		return res
	}

	return nil
}

func SnapHttpMethod(r *http.Request, method string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	if ok, _ := regexp.MatchString(`[^(GET|POST|PUT|PATCH)]`, method); ok {
		res.ResponseCode = snapCode.MissingMandatory
		res.ResponseMessage = "Invalid mandatory field [HttpMethod]"

		return res
	} else if r.Method != method {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Invalid Signature]"

		return res
	}

	return nil
}

func SnapEndpointUrl(pathname string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	if ok, _ := regexp.MatchString(`^.*(api/v1.0|openapi/v1.0)`, pathname); ok == false {
		res.ResponseCode = snapCode.MissingMandatory
		res.ResponseMessage = "Invalid mandatory field [EndpoinUrl]"

		return res
	}

	return nil
}

func SnapXSignature(r *http.Request, req *VerifySignature, security string, snapCode *SnapCodeRes) interface{} {
	var res SnapValidationRes = SnapValidationRes{}

	switch security {
	case "access-token/b2b":
		if err := SnapVerifyTokenB2B(req); err != nil {
			res.ResponseCode = snapCode.Unauthorized
			res.ResponseMessage = "Unauthorized. [Invalid Signature]"

			return res
		}
		break

	case "signature-service":
		if err := SnapVerifySignature(r, req); err != nil {
			res.ResponseCode = snapCode.Unauthorized
			res.ResponseMessage = "Unauthorized. [Invalid Signature]"

			return res
		}

		break
	}

	return nil
}

func SnapPrivateKey(privateKey string, envPrivateKey string, snapCode *SnapCodeRes) interface{} {
	var (
		res SnapValidationRes = SnapValidationRes{}
	)

	pemDecode, _ := pem.Decode([]byte(privateKey))
	if pemDecode == nil {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Unknown Client]"

		return res
	}

	switch pemDecode.Type {
	case "RSA PRIVATE KEY":
		_, err := x509.ParsePKCS1PrivateKey(pemDecode.Bytes)
		if err != nil {
			res.ResponseCode = snapCode.Unauthorized
			res.ResponseMessage = "Unauthorized. [Unknown Client]"

			return res
		}

		break

	case "PRIVATE KEY":
		_, err := x509.ParsePKCS8PrivateKey(pemDecode.Bytes)
		if err != nil {
			res.ResponseCode = snapCode.Unauthorized
			res.ResponseMessage = "Unauthorized. [Unknown Client]"

			return res
		}
		break
	}

	if ok := reflect.DeepEqual(privateKey, envPrivateKey); !ok {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Unknown Client]"

		return res
	}

	return nil
}

func SnapToken(db *sqlx.DB, clientId, authorization string, snapCode *SnapCodeRes) interface{} {
	var (
		res    SnapValidationRes    = SnapValidationRes{}
		secret SecretRes            = SecretRes{}
		token  string               = strings.TrimSpace(strings.Split(authorization, "Bearer ")[1])
		claims packages.ClaimsToken = packages.ClaimsToken{}
	)

	verifyToken, err := packages.VerifyToken(token)
	if err != nil {
		res.ResponseCode = snapCode.InvalidToken
		res.ResponseMessage = "Unauthorized. [Invalid Token]"

		return res
	}

	claimsByte, err := json.Marshal(&verifyToken.Claims)
	if err != nil {
		res.ResponseCode = snapCode.RequestParsingError
		res.ResponseMessage = "Parsing Error"

		return res
	}

	if err := json.Unmarshal([]byte(claimsByte), &claims); err != nil {
		res.ResponseCode = snapCode.RequestParsingError
		res.ResponseMessage = "Parsing Error"

		return res
	}

	row, err := QueryRow(context.Background(), db, &BuilderSelect{
		Table:  "secret sc",
		Fields: []string{"sc.access_token", " sc.expired_time"},
		Query: `
			WHERE sc.client_id = ? AND access_token = ? AND sc.type = ?
			ORDER BY sc.created_time
		`,
		Args: []string{claims.ClientId, verifyToken.Raw, "access-token-b2b"},
	})

	if err := row.Scan(&secret.AccessToken, &secret.ExpiredTime); err != nil {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Invalid Signature]"

		return res
	}

	if err := SnapAuthorization(token, secret.AccessToken, snapCode); err != nil {
		res.ResponseCode = err.(SnapValidationRes).ResponseCode
		res.ResponseMessage = err.(SnapValidationRes).ResponseMessage

		return err
	}

	location, _ := time.LoadLocation("Asia/Jakarta")
	datenow := time.Now().In(location).Local().Format(time.RFC3339)

	formatExpiredTime, _ := time.ParseInLocation(time.RFC3339, secret.ExpiredTime, location)
	expiredTime := formatExpiredTime.Local().Format(time.RFC3339)

	if expiredTime <= datenow {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = fmt.Sprintf("Unauthorized. The token expired at '%s' - invalid_token", expiredTime)

		return res
	} else if claims.ClientId != clientId {
		res.ResponseCode = snapCode.Unauthorized
		res.ResponseMessage = "Unauthorized. [Uknown Client]"

		return res
	}

	return nil
}
