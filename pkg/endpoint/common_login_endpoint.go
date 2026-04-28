package endpoint

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/liangboceo/yuanboot/abstractions/xlog"
	"github.com/liangboceo/yuanboot/pkg/httpclient"
	"github.com/liangboceo/yuanboot/web/context"
	"github.com/liangboceo/yuanboot/web/router"
)

func UseCommonLoginEndpoint(router router.IRouterBuilder) {
	config := router.GetConfiguration()
	var authServerUrl string
	var appid string
	var hasUrl, hasAppId bool
	if config != nil {
		appid, hasAppId = config.Get("yuanboot.application.server.app.appId").(string)
		authServerUrl, hasUrl = config.Get("yuanboot.application.server.uas.auth.auth-server-url").(string)
	}
	if !hasAppId {
		log.Printf("授权系统应用id未配置")
	}
	if !hasUrl {
		log.Printf("授权系统URL未配置")
	}
	router.POST("/login", func(ctx *context.HttpContext) {
		defer func() {
			if err := recover(); err != nil {
				ctx.JSON(http.StatusInternalServerError, context.H{
					"code":    http.StatusInternalServerError,
					"message": err,
				})
			}
		}()
		xlog.GetXLogger("CommonLoginEndpoint").Debugf("loaded commonLogin endpoint.")
		body := ctx.Input.GetBody()
		var reqMap map[string]string
		err := json.Unmarshal(body, &reqMap)
		if err != nil {
			// 处理解析错误
			log.Printf("JSON序列化失败: %v", err)
			panic("parse login body failed: " + err.Error())
			return
		}
		paramsMap := map[string]string{
			"uasToken": reqMap["token"],
			"appId":    appid, // 对应 appProperties.getAppId()
		}
		jsonBody, err := json.Marshal(paramsMap)
		if err != nil {
			log.Printf("JSON序列化失败: %v", err)
			panic("JSON序列化失败: " + err.Error())
			return
		}
		queryReq := httpclient.WithRequest()
		queryReq.WithContentTypeAsJson().
			WithBody(string(jsonBody)).
			POST(authServerUrl + "/uas/generateTempToken").
			SetTimeout(5)
		post, err := httpclient.NewClient().Post(queryReq)
		if err != nil {
			panic("接口请求异常: " + err.Error())
			return
		}
		// 先判断返回的是否为200:请求成功，如果不是则返回
		codeResult := post.BodyRaw.StatusCode
		resultB := post.Body
		if codeResult != 200 {
			ctx.JSON(codeResult, context.H{
				"code":    codeResult,
				"message": string(resultB),
			})
			return
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(post.String()), &result); err != nil {
			panic("解析失败：" + err.Error())
			return
		}

		// 逐层提取 temptoken
		data := result["data"].(map[string]interface{})
		tempToken := data["tempToken"].(string)
		if tempToken == "" {
			panic("登录失败，未获取到temptoken")
			return
		}
		// 步骤2：用临时令牌换取业务系统永久令牌
		// 构造请求参数
		params := map[string]string{
			"tempToken": tempToken,
			"appId":     appid, // 对应 appProperties.getAppId()
		}
		// 将参数转为 JSON 格式
		jsonBody, err = json.Marshal(params)
		if err != nil {
			panic("参数序列化失败: " + err.Error())
		}

		// 构造 POST 请求
		permReq := httpclient.WithRequest()
		permReq.WithContentTypeAsJson().
			WithBody(string(jsonBody)).
			POST(authServerUrl + "/uas/exchangePermToken").
			SetTimeout(5)

		// 发送请求
		// 1. 先获取 httpclient 的响应对象（类型为 *Response）
		clientResp, err := httpclient.NewClient().Post(permReq)
		if err != nil {
			panic("接口请求异常：" + err.Error())
			return
		}
		resultByte := clientResp.Body
		code := clientResp.BodyRaw.StatusCode
		if code != 200 {
			ctx.JSON(code, context.H{
				"code":    code,
				"message": string(resultByte),
			})
			return
		}
		var responseMap map[string]interface{}
		if err := json.Unmarshal(resultByte, &responseMap); err != nil {
			panic("解析响应 JSON 失败：" + err.Error())
			return
		}
		ctx.JSON(code, context.H{
			"code":    code,
			"message": "success",
			"data":    responseMap,
		})
		return
	})
	router.POST("/resource/limited/auth/tree", func(ctx *context.HttpContext) {
		xlog.GetXLogger("CommonLoginEndpoint").Debugf("loaded commonLogin endpoint.")
		defer func() {
			if err := recover(); err != nil {
				ctx.JSON(http.StatusInternalServerError, context.H{
					"code":    http.StatusInternalServerError,
					"message": err,
				})
			}
		}()
		userName := ctx.GetItem("userinfo").(string)
		if userName == "" {
			ctx.JSON(500, context.H{
				"code":    500,
				"message": "用户名为空！",
			})
			return
		}
		// 构造请求参数
		params := map[string]string{
			"appName":   appid,
			"loginName": userName,
		}
		jsonBody, err := json.Marshal(params)
		if err != nil {
			panic("参数序列化失败: " + err.Error())
		}
		req := httpclient.WithRequest()
		req.WithContentTypeAsJson().
			WithBody(string(jsonBody)).
			POST(authServerUrl + "/uas/resource/limited/auth/tree").
			SetTimeout(5)

		// 发送请求
		clientResp, err := httpclient.NewClient().Post(req)
		if err != nil {
			panic("接口请求异常：" + err.Error())
			return
		}
		resultByte := clientResp.Body
		code := clientResp.BodyRaw.StatusCode
		if code != 200 {
			ctx.JSON(code, context.H{
				"code":    code,
				"message": string(resultByte),
			})
			return
		}
		var responseMap map[string]interface{}
		if err := json.Unmarshal(resultByte, &responseMap); err != nil {
			panic("解析响应 JSON 失败：" + err.Error())
			return
		}
		ctx.JSON(code, context.H{
			"code":    code,
			"message": "success",
			"data":    responseMap["data"],
		})
	})

	router.POST("/getCurrentUser", func(ctx *context.HttpContext) {
		xlog.GetXLogger("CommonLoginEndpoint").Debugf("loaded commonLogin endpoint.")
		defer func() {
			if err := recover(); err != nil {
				ctx.JSON(http.StatusInternalServerError, context.H{
					"code":    http.StatusInternalServerError,
					"message": err,
				})
			}
		}()
		userName := ctx.GetItem("userinfo").(string)
		responseMap := map[string]string{
			"userName": userName,
		}
		ctx.JSON(200, context.H{
			"code":    200,
			"message": "success",
			"data":    responseMap,
		})
	})

}
