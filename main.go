package main

import (
	"fmt"
	. "github.com/CodyGuo/win"
	"github.com/gin-gonic/gin"
	"github.com/swgloomy/gutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	port = ":4500" //关机监听端口
	rt   *gin.Engine
)

func main() {
	rt = gin.Default()
	rt.Use(Cors())
	router(rt)

	go timingCloseWindows()

	go func() {
		err := rt.Run(port)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
			return
		}
	}()

	c := make(chan os.Signal, 1)
	// 信号处理
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)
	// 等待信号
	<-c
	os.Exit(0)
}

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method

		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-Type,AccessToken,X-CSRF-Token, Authorization, Token")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")

		//放行所有OPTIONS方法
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
		// 处理请求
		c.Next()
	}
}

func timingCloseWindows() {
	for true {
		timeStr := gutil.DateFormat(time.Now(), "yyyy-MM-dd hh")
		fmt.Println(timeStr)
		if timeStr == "2020-09-25 12" {
			go func() {
				getPrivileges()
				ExitWindowsEx(EWX_SHUTDOWN, 0)
			}()
		}
		time.Sleep(10 * time.Minute)
	}
}

func router(r *gin.Engine) {
	g := &r.RouterGroup
	g.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	g.GET("/close", close) // 短信发送接口
}

func close(c *gin.Context) {
	go func() {
		getPrivileges()
		ExitWindowsEx(EWX_SHUTDOWN, 0)
	}()
	c.String(http.StatusOK, "ok")
}

func getPrivileges() {
	var hToken HANDLE
	var tkp TOKEN_PRIVILEGES

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)
	LookupPrivilegeValueA(nil, StringToBytePtr(SE_SHUTDOWN_NAME), &tkp.Privileges[0].Luid)
	tkp.PrivilegeCount = 1
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	AdjustTokenPrivileges(hToken, false, &tkp, 0, nil, nil)
}
