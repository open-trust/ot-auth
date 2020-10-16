package tpl

import "github.com/teambition/gear"

// ErrorResponseType 定义了标准的 API 接口错误时返回数据模型
type ErrorResponseType = gear.ErrorResponse

// SuccessResponseType 定义了标准的 API 接口成功时返回数据模型
type SuccessResponseType struct {
	TotalSize     int         `json:"totalSize,omitempty"`
	NextPageToken string      `json:"nextPageToken,omitempty"`
	Result        interface{} `json:"result"`
}

// ResponseType ...
type ResponseType struct {
	ErrorResponseType
	SuccessResponseType
}
