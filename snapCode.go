package main

type SnapCodeRes struct {
	MissingMandatory    string `json:"missingMandatory,omitempty"`
	InvalidFieldFormat  string `json:"invalidFieldFormat,omitempty"`
	Unauthorized        string `json:"unauthorized,omitempty"`
	DuplicateExternalId string `json:"duplicateExternalId,omitempty"`
	InvalidToken        string `json:"invalidToken,omitempty"`
	GeneralError        string `json:"generalError,omitempty"`
	BadRequest          string `json:"badRequest,omitempty"`
	Success             string `json:"success,omitempty"`
	RequestParsingError string `json:"requestParsingError,omitempty"`
	RequestTimeout      string `json:"requestTimeout,omitempty"`
	BillNotFound        string `json:"billNotFound,omitempty"`
	BillPaid            string `json:"billPaid,omitempty"`
	BillAlreadyPaid     string `json:"billAlreadyPaid,omitempty"`
	BillExpired         string `json:"billExpired,omitempty"`
	Conflict            string `json:"conflict,omitempty"`
	UknownCLient        string `json:"uknownCLient,omitempty"`
}

func SnapCode(service string) SnapCodeRes {
	var (
		res SnapCodeRes = SnapCodeRes{}
	)

	switch service {

	case "utilities/signature-auth":
		res.MissingMandatory = "4000000"
		res.InvalidFieldFormat = "4000000"
		res.Unauthorized = "4010000"
		res.BadRequest = "4000000"
		res.GeneralError = "5007300"
		res.RequestTimeout = "5047302"
		res.Success = "2007300"

	}

	return res
}
