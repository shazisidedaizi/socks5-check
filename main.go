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
    Success bool   `json:"success"`
    Proxy   string `json:"proxy"`
    Country string `json:"country_code"`  
    Delay   int    `json:"elapsed_ms"`    

    Company struct {
        Type string `json:"type"`
    } `json:"company"`

    ASN struct {
        Type string `json:"type"`
    } `json:"asn"`
}

// ====================== TG 发送函数 ======================
func sendTelegramMessage(botToken, chatId, text string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
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
		if trim != "" {
			nodes = append(nodes, trim)
		}
	}
	return nodes, nil
}

// ====================== 调用 API 检测，带 3 次指数退避 ======================
func checkProxy(proxyStr, apiToken string) (CheckResp, error) {
	api := fmt.Sprintf(
		"https://check.xn--xg8h.netlib.re/check?proxy=%s&token=%s",
		url.QueryEscape(proxyStr), apiToken,
	)
	client := &http.Client{Timeout: 15 * time.Second}

	var result CheckResp
	var err error

	maxRetries := 3
	baseDelay := 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, e := client.Get(api)
		if e != nil {
			err = e
			fmt.Printf("请求失败 (%d/%d): %s\n", attempt, maxRetries, proxyStr)
		} else {
			err = json.NewDecoder(resp.Body).Decode(&result)
			resp.Body.Close()
			if err == nil && result.Success {
				break
			}
			if err == nil && !result.Success {
				fmt.Printf("节点无效 (%d/%d): %s\n", attempt, maxRetries, proxyStr)
			}
		}

		// 如果未成功且还有剩余重试次数，指数退避等待
		if attempt < maxRetries {
			wait := baseDelay * (1 << (attempt - 1)) // 2^0, 2^1, 2^2 秒
			fmt.Printf("等待 %v 后重试...\n", wait)
			time.Sleep(wait)
		}
	}

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
		if err != nil || !resp.Success {
			fmt.Printf("❌ 节点无效或请求失败: %s\n", node)
			continue
		}

		// 只要 company.type 或 asn.type 中有一个为 "isp" 就保留
		if resp.Company.Type != "isp" && resp.ASN.Type != "isp" {
			fmt.Printf("❌ 不是 ISP，跳过: %s\n", node)
			continue
		}

		// 格式化输出：socks5://username:password@host:port#country
		line := fmt.Sprintf("%s#%s", resp.Proxy, resp.Country)
		fmt.Printf("✅ 有效节点: %s\n", line)
		good = append(good, line)
	}

	// 拼接消息
	if len(good) == 0 {
		sendTelegramMessage(botToken, chatId, "本次扫描无有效代理节点")
		return
	}

	text := "可用代理列表：\n" + strings.Join(good, "\n")
	sendTelegramMessage(botToken, chatId, text)
}
