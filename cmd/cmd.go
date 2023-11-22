package cmd

import (
	"bufio"
	"fmt"
	"github.com/huntelaar112/goutils/sched"
	"github.com/huntelaar112/goutils/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
)

// each 10 minutes --> grep all json log (-90 day) --> .json file --> turn it to common log

var (
	// Used for flags.
	inputPath  string
	outputPath string
	latestdays string

	logger  = log.New()
	logfile = "/var/log/nginx2commonlog/nginx2commonlog.log"
	logf    *os.File

	rootCmd = &cobra.Command{
		Use:   "nginx2commonlog",
		Short: "Generate common log format file form nginxgen(sonnt) log",
		Long:  `Generate common log format file form nginxgen(sonnt) log`,
		Run:   RunRootCmd,
	}
)

func init() {
	cobra.OnInitialize(initConfig)

	initLogger()

	rootCmd.Flags().StringVarP(&inputPath, "inpath", "i", "", "path to nginxgen log directory (dir).")
	rootCmd.Flags().StringVarP(&outputPath, "outpath", "o", "", "path to save common log (file).")
	rootCmd.Flags().StringVarP(&latestdays, "latestdays", "d", "90", "grep log of last \"d\" days")
	rootCmd.MarkFlagsRequiredTogether("inpath", "outpath")
	rootCmd.MarkFlagRequired("inpath")
	rootCmd.MarkFlagRequired("outpath")

	viper.BindPFlag("inpath", rootCmd.Flags().Lookup("inpath"))
	viper.BindPFlag("outpath", rootCmd.Flags().Lookup("outpath"))
	viper.BindPFlag("latestdays", rootCmd.Flags().Lookup("latestdays"))

	if !utils.PathIsExist("/var/log/nginx/access.log") {
		utils.DirCreate("/var/log/nginx", 0775)
		err := utils.FileCreate("/var/log/nginx/access.log")
		if err != nil {
			logger.Error(err)
		}
	}
}

func initLogger() {
	utils.DirCreate("/var/log/nginx2commonlog", 0775)
	utils.FileCreate(logfile)
	var err error
	logf, err = os.OpenFile(logfile, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		logger.Error(err)
	}

	logger.SetOutput(logf)
	logger.SetLevel(log.InfoLevel)
	logger.SetReportCaller(true)
	logger.SetFormatter(&log.JSONFormatter{PrettyPrint: true})
}

func initConfig() {
	viper.AddConfigPath(".")
	viper.SetConfigType("toml")
	viper.SetConfigName("nginx2commonlog.toml")
	//viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Info("Config file not found in ./ folder, create one.")
		} else {
			logger.Info("Using config file:", viper.ConfigFileUsed())
		}
	}
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

// find  /mnt/containerdata/nginxgen/var_log_nginx -mtime +40 -type f > "${files}"
func RunRootCmd(cmd *cobra.Command, args []string) {
	viper.Set("inpath", inputPath)
	viper.Set("outpath", outputPath)
	err := viper.WriteConfigAs("./nginx2commonlog.toml")
	if err != nil {
		logger.Error(err)
	}
	sched.Every(15).EMinutes().Run(GenLogs)
	runtime.Goexit()
}

func GenCommonLastLogs(ip, op, ld string) error {
	logger.Info("Find the log files newer than " + ld + " days")
	findcmd := "find " + ip + " -mtime -" + ld + " -type f -name \"*access*\" -exec cat {} >" + op + " \\;"
	genjsonlogcmd := exec.Command("bash", "-c", findcmd)
	//#logger.Debug(findcmd)
	if logger.Level <= log.DebugLevel {
		fmt.Println(findcmd)
	}

	output, err := genjsonlogcmd.Output()
	if err != nil {
		logger.Error("Error executing command:", err)
		logger.Error(output)
		return fmt.Errorf("Error executing command:", err)
	}
	return err
}

func GenLogs(job *sched.Job) {
	err := GenCommonLastLogs(inputPath, "/tmp/temp-nginxgencommonlog.json", latestdays)
	if err != nil {
		logger.Error(err)
		return
	} // have json log at output path.
	file, err := os.Open("/tmp/temp-nginxgencommonlog.json")
	if err != nil {
		logger.Error(err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var resultFileContentChunk string

	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		count++
		resultFileContentChunk += json2common(line) + "\n"
		if count >= 500 {
			err := ioutil.WriteFile(outputPath, []byte(resultFileContentChunk), 0644)
			if err != nil {
				logger.Error("Error writing to result file:", err)
				return
			}
			count = 0
			resultFileContentChunk = ""
		}
	}
	if len(resultFileContentChunk) > 0 {
		err := ioutil.WriteFile(outputPath, []byte(resultFileContentChunk), 0644)
		if err != nil {
			logger.Error("Error writing to result file:", err)
			return
		}
	}
}

func json2common(line string) string {
	host := gjson.Get(line, "host")
	time_local := gjson.Get(line, "time_local")
	request := gjson.Get(line, "request")
	status := gjson.Get(line, "status")
	bytes_send := gjson.Get(line, "bytes_send")
	http_referer := gjson.Get(line, "http_referer")
	agent := gjson.Get(line, "agent")
	xforwaredfor := gjson.Get(line, "x-forwared-for")
	commonlog := checklogparammissing(host.String()) + " - " + "- " +
		"[" + checklogparammissing(time_local.String()) + "] " + "\"" + checklogparammissing(request.String()) + "\"" +
		" " + checklogparammissing(status.String()) + " " + checklogparammissing(bytes_send.String()) +
		" " + "\"" + checklogparammissing(http_referer.String()) + "\"" +
		" " + "\"" + checklogparammissing(agent.String()) + "\"" +
		" " + "\"" + checklogparammissing(xforwaredfor.String()) + "\""
	//#logger.Debug(commonlog)
	return commonlog
}

func checklogparammissing(str string) string {
	if str == "" {
		return "-"
	}
	return str
}
