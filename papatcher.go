// Copyright ©2014-2019 Planetary Annihilation Inc. All rights reserved.

package main

import "bufio"
import "bytes"
import "compress/gzip"
import "crypto/sha1"
import _ "crypto/sha256"
import "crypto/tls"
import "crypto/x509"
import "encoding/hex"
import "encoding/json"
import "flag"
import "fmt"
import "io"
import "io/ioutil"
import "net/http"
import "os"
import "os/user"
import "os/exec"
import "path/filepath"
import "runtime"
import "sort"
import "strconv"
import "strings"
import "sync"
import "time"



var cacerts_pem = `
-----BEGIN CERTIFICATE-----
MIIESTCCAzGgAwIBAgITBn+UV4WH6Kx33rJTMlu8mYtWDTANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
IDFCMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDCThZn3c68asg3Wuw6MLAd5tES6BIoSMzoKcG5blPVo+sDORrMd4f2AbnZ
cMzPa43j4wNxhplty6aUKk4T1qe9BOwKFjwK6zmxxLVYo7bHViXsPlJ6qOMpFge5
blDP+18x+B26A0piiQOuPkfyDyeR4xQghfj66Yo19V+emU3nazfvpFA+ROz6WoVm
B5x+F2pV8xeKNR7u6azDdU5YVX1TawprmxRC1+WsAYmz6qP+z8ArDITC2FMVy2fw
0IjKOtEXc/VfmtTFch5+AfGYMGMqqvJ6LcXiAhqG5TI+Dr0RtM88k+8XUBCeQ8IG
KuANaL7TiItKZYxK1MMuTJtV9IblAgMBAAGjggE7MIIBNzASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUWaRmBlKge5WSPKOUByeW
dFv5PdAwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAow
CAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQCFkr41u3nPo4FCHOTjY3NTOVI1
59Gt/a6ZiqyJEi+752+a1U5y6iAwYfmXss2lJwJFqMp2PphKg5625kXg8kP2CN5t
6G7bMQcT8C8xDZNtYTd7WPD8UZiRKAJPBXa30/AbwuZe0GaFEQ8ugcYQgSn+IGBI
8/LwhBNTZTUVEWuCUUBVV18YtbAiPq3yXqMB48Oz+ctBWuZSkbvkNodPLamkB2g1
upRyzQ7qDn1X8nn8N8V7YJ6y68AtkHcNSRAnpTitxBKjtKPISLMVCx7i4hncxHZS
yLyKQXhw2W2Xs0qLeC1etA+jTGDK4UfLeC0SF7FSi8o5LL21L8IzApar2pR/
-----END CERTIFICATE-----

`



type LoginParams struct {
	TitleId int
	AuthMethod string
	UberName string
	Password string
}

type LoginResponse struct {
	SessionTicket string
	UberName string
	UberId uint64
	DisplayName string
	UberIdString string
}

type FailResponse struct {
	ErrorCode int
	Message string
}


type StreamsResponse struct {
	Streams []StreamInfo
}

type StreamInfo struct {
	TitleId int
	StreamName string
	BuildId string
	Description string
	DownloadUrl string
	AuthSuffix string
	ManifestName string
	TitleFolder string
}


type WorkItem struct {
	Download int64
	Validate int64
	Write int64
}



type ManifestEntry struct {
	Filename string
	ChecksumStr string `json:"checksum"`
	ChecksumZStr string `json:"checksumZ"`
	SizeStr string `json:"size"`
	SizeZStr string `json:"sizeZ"`
	OffsetStr string `json:"offset"`
	Executable bool

	Checksum []byte `json:"-"`
	ChecksumZ []byte `json:"-"`
	Size int64 `json:"-"`
	SizeZ int64 `json:"-"`
	Offset int64 `json:"-"`
}

type ManifestBundle struct {
	ChecksumStr string `json:"checksum"`
	SizeStr string `json:"size"`
	Entries []*ManifestEntry

	Checksum []byte `json:"-"`
	Size int64 `json:"-"`
}

type Manifest struct {
	Version string
	PatchesFrom string
	Bundles []*ManifestBundle
}




type Throttle chan struct{}

func NewThrottle(cap int) Throttle {
	return make(chan struct{}, cap)
}

func (t Throttle) Enter() {
	t <- struct{}{}
}

func (t Throttle) Exit() {
	<- t
}




func panicIf(err error) {
	if err != nil {
		panic(err)
	}
}


func readLine(reader *bufio.Reader, prompt string) (result string, err error) {
	os.Stdout.Write([]byte(prompt))
	result,err = reader.ReadString('\n')
	if err == nil {
		result = strings.TrimSuffix(result[:len(result)-1], "\r")
	} else if err == io.EOF {
		if result != "" {
			err = nil
		} else {
			err = io.ErrUnexpectedEOF
		}
	}
	return
}


var client *http.Client

func init() {
	cacerts := x509.NewCertPool()
	worked := cacerts.AppendCertsFromPEM([]byte(cacerts_pem))
	if !worked {
		panic("could not parse CA certs")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{ RootCAs: cacerts },
	}
	client = &http.Client{ Transport: tr }
}

var platform_map = map[string]string {
	"darwin": "OSX",
	"linux": "Linux",
        "windows": "Windows",
}



func main() {
	os.Exit(run())
}


func run() int {

	var err error

	start := time.Now()


	platform,ok := platform_map[runtime.GOOS]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unrecognied result from runtime.GOOS: %v.\n", runtime.GOOS)
		return 1
	}


	ncpus := runtime.NumCPU()
	runtime.GOMAXPROCS(ncpus)


	usr,err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not figure out the current user: %v", err)
		return 1
	}


	var devenv bool
	flag.BoolVar(&devenv, "dev", false, "Use PAnet dev environment")

	var desired_stream string
	flag.StringVar(&desired_stream, "stream", "stable", "Stream to download/update")

	var quiet bool
	flag.BoolVar(&quiet, "quiet", false, "No status updates")

	var root_dir string
	flag.StringVar(&root_dir, "dir", "", "Target directory to patch")

	var update_only bool
	flag.BoolVar(&update_only, "update-only", false, "Only do an update, don't launch")


	flag.Parse()

	var urlroot string
	if (devenv) {
		if !quiet {
			fmt.Println("Using dev environment")
		}
		urlroot = "https://service.dev.planetaryannihilation.net"
	} else {
		urlroot = "https://service.planetaryannihilation.net"
	}

	stdin_reader := bufio.NewReader(os.Stdin)

	var username string;
	if flag.NArg() < 1 {
		username,err = readLine(stdin_reader, "Username: ")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		username = flag.Arg(0)
	}

	var password string;
	if flag.NArg() < 2 {
		password,err = readLine(stdin_reader, "Password: ")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		password = flag.Arg(1)
	}


	if !quiet {
		fmt.Println("logging in...");
	}
	login_response := login(username, password, urlroot)
	if login_response == nil {
		return 1
	}



	if !quiet {
		fmt.Println("requesting streams...");
	}

	req,err := http.NewRequest("GET", urlroot + "/Launcher/ListStreams?Platform=" + platform, nil)
	panicIf(err)
	req.Header.Set("X-Authorization", login_response.SessionTicket)
	resp,err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	resp_bytes,err := ioutil.ReadAll(resp.Body)
	panicIf(err)
	panicIf(resp.Body.Close())
	if (resp.StatusCode != 200) {
		fmt.Fprintf(os.Stderr, "download failed: %v\n", resp.Status)
		os.Stderr.Write(resp_bytes)
		return 1
	}

	streams := make(map[string]StreamInfo)

	var streams_response StreamsResponse
	panicIf(json.Unmarshal(resp_bytes, &streams_response))
	for _,stream := range streams_response.Streams {
		streams[stream.StreamName] = stream
	}

	stream,found := streams[desired_stream]
	if !found {
		fmt.Fprintf(os.Stderr, "Unknown stream: %v\nOptions:\n", desired_stream)
		for _,stream = range streams_response.Streams {
			fmt.Fprintf(os.Stderr, "    %v\n", stream.StreamName)
		}
		return 1
	}


	if root_dir == "" {
		root_dir = filepath.Join(usr.HomeDir, ".local", "Uber Entertainment", "Planetary Annihilation")
	}
	if !quiet {
		fmt.Printf("Using target directory %v\n", root_dir)
	}
	err = os.MkdirAll(root_dir, 0777)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}


	manifest_url := fmt.Sprintf("%v/%v/%v", stream.DownloadUrl, stream.TitleFolder, stream.ManifestName)

	if !quiet {
		fmt.Printf("downloading manifest %v\n", manifest_url)
	}

	resp,err = client.Get(manifest_url + stream.AuthSuffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %v\n", err)
		return 1
	}
	reader,err := gzip.NewReader(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %v\n", err)
		return 1
	}
	manifest_bytes,err := ioutil.ReadAll(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %v\n", err)
		return 1
	}
	err = resp.Body.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %v\n", err)
		return 1
	}
	if (resp.StatusCode != 200) {
		fmt.Fprintf(os.Stderr, "download failed: %v\n", resp.Status)
		os.Stderr.Write(manifest_bytes)
		return 1
	}


	var manifest Manifest
	if err = json.Unmarshal(manifest_bytes, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "Decoding manifest failed: %v\n", err)
		return 1
	}

	total_work, files, err := validateManifest(&manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Manifest broken: %v\n", err)
		return 1
	}

	download_prefix := fmt.Sprintf("%v/%v/hashed/", stream.DownloadUrl, stream.TitleFolder)

	game_dir := filepath.Join(root_dir, stream.StreamName)

	diag_chan := make(chan string, 3)
	status_chan := make(chan string, 3)
	diag_done := make(chan struct{})

	go func () {
		dc := diag_chan
		sc := status_chan

		var status string
		for dc != nil || sc != nil {
			select {
			case item,okay := <-dc:
				if !okay {
					dc = nil
				}
				if !quiet {
					fmt.Printf("\r%v\n%v", item, status)
				}

			case new_status,okay := <-sc:
				if !okay {
					fmt.Printf("\r%-*s", len(status), "")
					status = ""
					sc = nil
				} else if !quiet {
					fmt.Printf("\r%-*s", len(status), new_status)
					status = new_status
				}
			}
		}
		diag_done <- struct{}{}
		return
	}()


	errors_chan := make(chan string, 3)
	errors_done := make(chan []string)

	go func () {
		errors := make([]string, 0)
		for err := range errors_chan {
			errors = append(errors, err)
			diag_chan <- "ERROR: " + err
		}
		errors_done <- errors
	}()

	progress_chan := make(chan WorkItem, 1)
	progress_done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(time.Millisecond * 500)
		var cum WorkItem
		for {
			select {
			case item,okay := <-progress_chan:
				if !okay {
					diag_chan <- fmt.Sprintf("D: %5.1f%%  V: %5.1f%%  W: %5.1f%%",
						float64(cum.Download) * 100.0 / float64(total_work.Download),
						float64(cum.Validate) * 100.0 / float64(total_work.Validate),
						float64(cum.Write) * 100.0 / float64(total_work.Write))
					close(status_chan)
					progress_done <- struct{}{}
					return
				}
				cum.Download += item.Download
				cum.Validate += item.Validate
				cum.Write += item.Write

			case _ = <-ticker.C:
				status_chan <- fmt.Sprintf("D: %5.1f%%  V: %5.1f%%  W: %5.1f%%",
					float64(cum.Download) * 100.0 / float64(total_work.Download),
					float64(cum.Validate) * 100.0 / float64(total_work.Validate),
					float64(cum.Write) * 100.0 / float64(total_work.Write))
			}
		}
	}()

	throttle := NewThrottle(ncpus)
	var waitgroup sync.WaitGroup
	waitgroup.Add(len(manifest.Bundles))


	cache_dir := filepath.Join(root_dir, ".cache")

	go func () {
		for _,bundle := range manifest.Bundles {
			throttle.Enter()
			go func (bundle *ManifestBundle) {
				defer throttle.Exit()
				processBundle(bundle, download_prefix, stream.AuthSuffix, cache_dir, game_dir, diag_chan, errors_chan, progress_chan)
				waitgroup.Done()
			}(bundle)
		}
	}()


	var removes []string
	filepath.Walk(game_dir, func (path string, info os.FileInfo, err error) error {
		filename := strings.Replace(path[len(game_dir):], "\\", "/", -1)
		if !files[filename] {
			// diag_chan <- fmt.Sprintf("removing %v", filename)
			removes = append(removes, path)
		}
		return nil
	})

	for i := len(removes)-1; i >= 0; i-- {
		path := removes[i]
		err = os.Remove(path)
		if err != nil {
			errors_chan <- fmt.Sprintf("removal of extra file %v failed: %v", path, err)
		}
	}

	waitgroup.Wait()

	close(progress_chan)
	<- progress_done


	close(errors_chan)
	errors := <- errors_done

	close(diag_chan)
	<- diag_done

	end := time.Now()
	elapsed := end.Sub(start)
	if !quiet {
		fmt.Printf("\nFinished in %v\n", elapsed)
	}

	if len(errors) > 0 {
		fmt.Fprintln(os.Stderr, "\nUpdate failed:")
		for _,err := range errors {
			fmt.Fprintln(os.Stderr, "    ", err)
		}
		return 1
	}

	if update_only {
		return 0
	}

	var args = make([]string,0,5)
	if devenv {
		args = append(args, "--ubernetdev")
	}
	args = append(args, "--ticket", login_response.SessionTicket)
	cmd := exec.Command(filepath.Join(game_dir, "PA"), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "\nLaunching PA failed:", err)
		return 1
	}

	if err = cmd.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, "\nPA exited with non-zero status: ", err)
		return 1
	}

	return 0
}

func login(username, password, urlroot string) (result *LoginResponse) {

	login_params := LoginParams{
		TitleId: 4,
		AuthMethod: "UberCredentials",
		UberName: username,
		Password: password,
	}

	login_params_json,err := json.Marshal(login_params)
	if err != nil {
		panic(err);
	}

	resp,err := client.Post(urlroot + "/GC/Authenticate", "application/json", bytes.NewBuffer(login_params_json))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not contact %v:\n    %v\n", urlroot, err)
		return nil
	}

	resp_bytes,err := ioutil.ReadAll(resp.Body)
	panicIf(err)
	panicIf(resp.Body.Close())
	if (resp.StatusCode != 200) {

		var fail_response FailResponse
		err = json.Unmarshal(resp_bytes, &fail_response)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Login failed: %v (code=%v)\n", fail_response.Message, fail_response.ErrorCode)
			return nil
		}
		fmt.Fprintf(os.Stderr, "login failed with HTTP status %#v\n", resp.Status)
		if (len(resp_bytes) > 0) {
			fmt.Fprintf(os.Stderr, "response details:\n")
			os.Stderr.Write(resp_bytes)
			if resp_bytes[len(resp_bytes)-1] != '\n' {
				fmt.Fprintln(os.Stderr)
			}
		}
		return nil
	}

	result = new(LoginResponse)
	panicIf(json.Unmarshal(resp_bytes, result))
	return
}


func validateManifest(manifest *Manifest) (work WorkItem, files map[string]bool, err error) {

	files = make(map[string]bool)

	seen := make(map[string]*ManifestBundle)
	uniques := make([]*ManifestBundle, 0, len(manifest.Bundles))

	for _,bundle := range manifest.Bundles {
		if bundle.Checksum,err = hex.DecodeString(bundle.ChecksumStr); err != nil {
			return
		}

		if bundle.Size,err = strconv.ParseInt(bundle.SizeStr, 10, 64); err != nil {
			return
		}

		existing,found := seen[bundle.ChecksumStr]
		if found {
			if existing.Size != bundle.Size {
				err = fmt.Errorf("Bundle %v repeated but with different sizes (%v and %v)", bundle.Checksum, bundle.Size, existing.Size)
				return
			}
			existing.Entries = append(existing.Entries, bundle.Entries...)
		} else {
			seen[bundle.ChecksumStr] = bundle
			uniques = append(uniques, bundle)
			work.Download += bundle.Size
			work.Validate += bundle.Size
			work.Write += bundle.Size
		}

		for _,entry := range bundle.Entries {
			if entry.Checksum,err = hex.DecodeString(entry.ChecksumStr); err != nil {
				return
			}
			if entry.Offset,err = strconv.ParseInt(entry.OffsetStr, 10, 64); err != nil {
				return
			}
			if entry.Size,err = strconv.ParseInt(entry.SizeStr, 10, 64); err != nil {
				return
			}
			if entry.SizeZ,err = strconv.ParseInt(entry.SizeZStr, 10, 64); err != nil {
				return
			}

			filename := entry.Filename
			for !files[filename] {
				files[filename] = true
				slash := strings.LastIndex(filename, "/")
				if slash == -1 {
					break
				}
				filename = filename[:slash]
			}

			work.Validate += entry.Size
			work.Write += entry.Size
		}
	}

	manifest.Bundles = uniques

	return
}




type ByOffset []*ManifestEntry

func (a ByOffset) Len() int {
	return len(a)
}
func (a ByOffset) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a ByOffset) Less(i, j int) bool {
	return a[i].Offset < a[j].Offset
}


type DownloadWrapper struct {
	file io.ReadCloser
	progress_chan chan<- WorkItem
}

func (dw *DownloadWrapper) Read(bytes []byte) (n int, err error) {
	n,err = dw.file.Read(bytes)
	if n > 0 {
		dw.progress_chan <- WorkItem{Download: int64(n), Write: int64(n)}
	}
	return
}

func (dw *DownloadWrapper) Close() error {
	return dw.file.Close()
}


type WriteWrapper struct {
	file io.ReadCloser
	progress_chan chan<- WorkItem
}

func (ww *WriteWrapper) Read(bytes []byte) (n int, err error) {
	n,err = ww.file.Read(bytes)
	if n > 0 {
		ww.progress_chan <- WorkItem{Write: int64(n)}
	}
	return
}

func (ww *WriteWrapper) Close() error {
	return ww.file.Close()
}




func processBundle(bundle *ManifestBundle, download_prefix, auth_suffix, cache_dir, game_dir string, diag_chan, errors_chan chan<- string, progress_chan chan<- WorkItem) {

	cache_file := filepath.Join(cache_dir, strings.ToLower(bundle.ChecksumStr))

	downloaded := false

	download_factory := func () (io.ReadCloser) {
		url := download_prefix + bundle.ChecksumStr
		// diag_chan <- fmt.Sprintf("downloading %v", url)

		resp,err := client.Get(url + auth_suffix)
		if err != nil {
			errors_chan <- fmt.Sprintf("download of %v failed: %v", url, err)
			return nil
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			errors_chan <- fmt.Sprintf("download of %v failed: %v", url, resp.Status)
			return nil
		}

		downloaded = true

		return &DownloadWrapper{file: resp.Body, progress_chan: progress_chan}
	}

	file := verifyOrRecreate(cache_file, bundle.Checksum, bundle.Size, false, download_factory, true, diag_chan, errors_chan, progress_chan)
	if file == nil {
		return
	}

	if !downloaded {
		progress_chan <- WorkItem{Download: bundle.Size}
	}

	defer file.Close()

	sort.Sort(ByOffset(bundle.Entries))

	for _,entry := range bundle.Entries {

		dst_file := game_dir + entry.Filename
		extract_factory := func () (io.ReadCloser) {
			//diag_chan <- fmt.Sprintf("extracting %v from %v [offset %v]", dst_file, cache_file, entry.Offset)
			var err error
			if _,err = file.Seek(entry.Offset, os.SEEK_SET); err != nil {
				errors_chan <- fmt.Sprintf("extraction of %v failed: %v", entry.Filename, err)
				return nil
			}
			var reader io.ReadCloser
			if entry.SizeZ != 0 {
				reader,err = gzip.NewReader(&io.LimitedReader{R: file, N: entry.SizeZ})
				if err != nil {
					errors_chan <- fmt.Sprintf("extraction of %v failed: %v", entry.Filename, err)
					return nil
				}
			} else {
				reader = ioutil.NopCloser(&io.LimitedReader{R: file, N: entry.Size})
			}
			return &WriteWrapper{file: reader, progress_chan: progress_chan}
		}

		verifyOrRecreate(dst_file, entry.Checksum, entry.Size, entry.Executable, extract_factory, false, diag_chan, errors_chan, progress_chan)
	}
}


func verifyOrRecreate(filename string, checksum []byte, length int64, executable bool, factory func () io.ReadCloser, leave_open bool, diag_chan, errors_chan chan<- string, progress_chan chan<- WorkItem) *os.File {

	file,err := os.Open(filename)

	if err == nil {
		//diag_chan <- fmt.Sprintf("verifying %v (length %v)", filename, length)
		hash := sha1.New()
		_,err := io.Copy(hash, file)
		progress_chan <- WorkItem{Validate: length}
		if err != nil {
			diag_chan <- fmt.Sprintf("%v: %v", filename, err)
			file.Close()
		} else if calculated := hash.Sum(make([]byte, 0, hash.Size())); bytes.Compare(checksum, calculated) != 0 {
			diag_chan <- fmt.Sprintf("%v: checksum wrong, got %v wanted %v", filename, hex.EncodeToString(calculated), hex.EncodeToString(checksum))
			file.Close()
		} else {
			progress_chan <- WorkItem{Write: length}
			fileinfo,err := file.Stat()
			if err != nil {
				errors_chan <- err.Error()
				return nil
			}
			exe_bits := fileinfo.Mode() & 0111
			if executable {
				read_bits := fileinfo.Mode() & 0444
				if (read_bits >> 2 != exe_bits) {
					err = file.Chmod(fileinfo.Mode() | (read_bits >> 2))
					if err != nil {
						errors_chan <- err.Error()
						return nil
					}
				}
			} else {
				if exe_bits != 0 {
					err = file.Chmod(fileinfo.Mode() ^ exe_bits);
					if err != nil {
						errors_chan <- err.Error()
						return nil
					}
				}
			}

			if leave_open {
				return file
			} else {
				file.Close()
				return nil
			}
		}
	} else {
		progress_chan <- WorkItem{Validate: length}
	}

	if err = os.MkdirAll(filepath.Dir(filename), os.ModePerm); err != nil {
		errors_chan <- err.Error()
		return nil
	}

	src := factory()
	if src == nil {
		return nil
	}

	var mode os.FileMode
	if executable { mode = 0777 } else { mode = 0666 }
	dst,err := os.OpenFile(filename + ".new", os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		src.Close()
		errors_chan <- err.Error()
		return nil
	}

	hash := sha1.New()
	if _,err = io.Copy(io.MultiWriter(dst, hash), src); err != nil {
		src.Close()
		dst.Close()
		errors_chan <- err.Error()
		return nil
	}

	if err = dst.Close(); err != nil {
		src.Close()
		errors_chan <- err.Error()
		return nil
	}

	src.Close()

	calculated := hash.Sum(make([]byte, 0, hash.Size()))
	if bytes.Compare(checksum, calculated) != 0 {
		errors_chan <- fmt.Sprintf("%v: checksum wrong, got %v wanted %v", filename, hex.EncodeToString(calculated), hex.EncodeToString(checksum))
		return nil
	}

	if err = os.Rename(filename + ".new", filename); err != nil {
		errors_chan <- err.Error()
		return nil
	}

	if !leave_open {
		return nil
	}

	result,err := os.Open(filename)
	if err != nil {
		errors_chan <- err.Error()
		return nil
	}

	return result
}

