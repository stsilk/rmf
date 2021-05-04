package rmf

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
)

/*
CHECKLIST FORMAT

-Checklist
	- Asset
	- Stigs
		- Istig
			- StigInfo
				- SiData
			- Vulns
				- Stig Data
*/

//Structs based on checklist DOM
type Checklist struct {
	XMLName xml.Name `xml:"CHECKLIST"`
	Asset   Asset    `xml:"ASSET"`
	Stigs   Stigs    `xml:"STIGS"`
}

type Asset struct {
	XMLName   xml.Name `xml:"ASSET"`
	Role      string   `xml:"ROLE"`
	AssetType string   `xml:"ASSET_TYPE"`
	Hostname  string   `xml:"HOST_NAME"`
	HostIP    string   `xml:"HOST_IP"`
	HostMac   string   `xml:"HOST_MAC"`
	HostFQDN  string   `xml:"HOST_FQDN"`
	TechArea  string   `xml:"TECH_AREA"`
	TargetKey string   `xml:"TARGET_KEY"`
	WebOrDB   string   `xml:"WEB_OR_DATABASE"`
	WebDBSite string   `xml:"WEB_DB_SITE"`
	WebDBInst string   `xml:"WEB_DB_INSTANCE"`
}

type Stigs struct {
	XMLName xml.Name `xml:"STIGS"`
	Istig   Istig    `xml:"iSTIG"`
}

type Istig struct {
	XMLName  xml.Name `xml:"iSTIG"`
	StigInfo StigInfo `xml:"STIG_INFO"`
	Vulns    []Vuln   `xml:"VULN"`
}

type StigInfo struct {
	XMLName xml.Name `xml:"STIG_INFO"`
	SiData  []SiData `xml:"SI_DATA"`
}

type SiData struct {
	XMLName xml.Name `xml:"SI_DATA"`
	SidName string   `xml:"SID_NAME"`
	SidData string   `xml:"SID_DATA"`
}

type Vuln struct {
	XMLName               xml.Name       `xml:"VULN"`
	StigDataMeta          []StigDataMeta `xml:"STIG_DATA"`
	StigData              StigData
	FindingDetails        string `xml:"FINDING_DETAILS"`
	Comments              string `xml:"COMMENTS"`
	Status                string `xml:"STATUS"`
	SeverityOverride      string `xml:"SEVERITY_OVERRIDE"`
	SeverityJustification string `xml:"SEVERITY_JUSTIFICATION"`
}

type StigData struct {
	VulnNum                  string `json:"VulnNUm"`
	Severity                 string `json:"Severity"`
	GroupTitle               string `json:"GroupTitle"`
	RuleID                   string `json:"RuleID"`
	RuleVer                  string `json:"RuleVer"`
	RuleTitle                string `json:"RuleTitle"`
	VulnDiscuss              string `json:"VulnDiscuss"`
	IAControls               string `json:"IAControls"`
	CheckContent             string `json:"CheckContent"`
	FixText                  string `json:"FixText"`
	FalseNegatives           string `json:"FalseNegatives"`
	Documentable             string `json:"Documentable"`
	Mitigations              string `json:"Mitigations"`
	PotentialImpact          string `json:"PotentialImpact"`
	ThirdPartyTools          string `json:"ThirdPartyTools"`
	MitigationControl        string `json:"MitigationControl"`
	Responsibility           string `json:"Responsibility"`
	SecurityOverrideGuidance string `json:"SecurityOverrideGuidance"`
	CheckContentRef          string `json:"CheckContentRef"`
	Weight                   string `json:"Weight"`
	Class                    string `json:"Class"`
	STIGRef                  string `json:"STIGRef"`
	TargetKey                string `json:"TargetKey"`
	STIGUUID                 string `json:"STIGUUID"`
	CCIREF                   string `json:"CCIREF"`
}

type StigDataMeta struct {
	XMLName  xml.Name `xml:"STIG_DATA"`
	VulnAttr string   `xml:"VULN_ATTRIBUTE"`
	AttrData string   `xml:"ATTRIBUTE_DATA"`
}

type StatusCount struct {
	Open          int
	NotApplicable int
	NotAFinding   int
	NotReviewed   int
}

func ParseChecklist(checklistBytes []byte) Checklist {
	checklist := new(Checklist)
	//Unmarshal XML data into checklist structure
	xml.Unmarshal(checklistBytes, &checklist)

	//Loop through STIG vulnerabilities
	for i, x := range checklist.Stigs.Istig.Vulns {
		stigData := make(map[string]string)

		//Loop through each StigData structure and create a map
		for _, z := range x.StigDataMeta {
			stigData[strings.ReplaceAll(z.VulnAttr, "_", "")] = z.AttrData
		}

		//Marshal the stigData into json then unmarshal into
		data, _ := json.Marshal(stigData)
		err := json.Unmarshal(data, &checklist.Stigs.Istig.Vulns[i].StigData)
		if err != nil {
			fmt.Println("Could not unmarshal stigData", err)
		}
	}
	return *checklist
}

func CountStatus(checklist Checklist) StatusCount {
	var statusCount StatusCount
	for _, x := range checklist.Stigs.Istig.Vulns {
		switch status := x.Status; status {
		case "Open":
			statusCount.Open++

		case "NotAFinding":
			statusCount.NotAFinding++

		case "Not_Reviewed":
			statusCount.NotReviewed++

		case "Not_Applicable":
			statusCount.NotApplicable++
		}
	}
	return statusCount
}
