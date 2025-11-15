package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ====================== API 结果结构 ======================
type CheckResp struct {
	Ok      bool   `json:"ok"`
	Country string `json:"country"`
	Delay   int    `json:"delay"`
}

// ====================== TG 发送函数 ======================
func sendTelegramMessage(botToken, chatId, text string) error {
	apiURL := fmt.Sprintf(
		"https://api.telegram.org/bot%s/sendMessage",
		botToken,
	)
	data := url.Values{}
	data.Set("chat_id", chatId)
	data.Set("text", text)

	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ====================== 下载节点列表 ======================
func fetchNodesFromURL(rawURL string) ([]string, error) {
	resp, err := http.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var nodes []string
	reader := bufio.NewReader(resp.Body)

	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		trim := strings.TrimSpace(string(line))
		if trim == "" {
			continue
		}
		nodes = append(nodes, trim)
	}
	return nodes, nil
}

// ====================== 调用 API 检测 ======================
func checkProxy(proxy, apiToken string) (CheckResp, error) {
	api := fmt.Sprintf(
		"https://check.xn--xg8h.netlib.re/check?proxy=%s&token=%s",
		url.QueryEscape(proxy), apiToken,
	)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(api)
	if err != nil {
		return CheckResp{}, err
	}
	defer resp.Body.Close()

	var result CheckResp
	err = json.NewDecoder(resp.Body).Decode(&result)
	return result, err
}

// ========================= 主程序 =========================
func main() {
	botToken := os.Getenv("BOT_TOKEN")
	chatId := os.Getenv("CHAT_ID")
	apiToken := os.Getenv("API_TOKEN")
	nodesURL := os.Getenv("NODES_URL")

	if botToken == "" || chatId == "" || apiToken == "" || nodesURL == "" {
		fmt.Println("缺少必要的环境变量，请检查 GitHub Secrets")
		os.Exit(1)
	}

	// 读取节点
	nodes, err := fetchNodesFromURL(nodesURL)
	if err != nil {
		fmt.Println("下载节点列表失败:", err)
		os.Exit(1)
	}

	var good []string
	for _, node := range nodes {
		resp, err := checkProxy(node, apiToken)
		if err != nil {
			continue
		}
		if resp.Ok {
			good = append(good, fmt.Sprintf("%s  %dms  %s", node, resp.Delay, resp.Country))
		}
	}

	// 拼接消息
	if len(good) == 0 {
		sendTelegramMessage(botToken, chatId, "本次扫描无有效代理节点")
		return
	}

	text := "可用代理列表：\n" + strings.Join(good, "\n")
	sendTelegramMessage(botToken, chatId, text)
}
