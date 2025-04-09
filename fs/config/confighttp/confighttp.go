package confighttp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/unknwon/goconfig"
)

type HttpStorage struct {
	mu sync.Mutex           // to protect the following variables
	gc *goconfig.ConfigFile // config file loaded - not thread safe
	iv string
}

func Install() {
	config.SetData(NewHttpStorage())
}

func NewHttpStorage() *HttpStorage {
	rs := &HttpStorage{}
	configPath := config.GetConfigPath()
	if configPath == "" {
		return rs
	}
	rdx := strings.LastIndex(configPath, "#")
	if rdx != -1 {
		rs.iv = configPath[rdx+1:]
		configPath = configPath[:rdx]
		config.SetConfigPath(configPath)
	}
	return rs
}

// load the config from permanent storage, decrypting if necessary
//
// mu must be held when calling this
func (s *HttpStorage) load() (err error) {
	// Make sure we have a sensible default even when we error
	defer func() {
		if s.gc == nil {
			s.gc, _ = goconfig.LoadFromReader(bytes.NewReader([]byte{}))
		}
	}()

	configPath := config.GetConfigPath()
	if configPath == "" {
		return config.ErrorConfigFileNotFound
	}
	// If the config path contains "://new/" then we don't need to load it
	if strings.Contains(configPath, "://new/") {
		return
	}

	cli := &http.Client{Timeout: 30 * time.Second}
	resp, err := cli.Get(configPath)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return config.ErrorConfigFileNotFound
		}
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP:%d, %s", resp.StatusCode, string(msg))
	}
	defer fs.CheckClose(resp.Body, &err)

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if s.iv != "" {
		data, err = SymmetricDecrypt(data, EncryptKey, []byte(s.iv))
		if err != nil {
			return err
		}
	}

	gc, err := goconfig.LoadFromReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	s.gc = gc

	return nil
}

// Load the config from permanent storage, decrypting if necessary
func (s *HttpStorage) Load() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// Save the config to permanent storage, encrypting if necessary
func (s *HttpStorage) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := config.GetConfigFilename()
	if filename == "" {
		return fmt.Errorf("config filename is empty")
	}
	fp, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer fs.CheckClose(fp, &err)
	buf := &bytes.Buffer{}
	err = goconfig.SaveConfigData(s.gc, buf)
	if err != nil {
		return err
	}
	var data []byte
	if s.iv != "" {
		data, err = SymmetricEncrypt(buf.Bytes(), EncryptKey, []byte(s.iv))
		if err != nil {
			return err
		}
	} else {
		data = buf.Bytes()
	}
	_, err = fp.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// Serialize the config into a string
func (s *HttpStorage) Serialize() (string, error) {
	return "<http storage>", nil
}

// HasSection returns true if section exists in the config file
func (s *HttpStorage) HasSection(section string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.gc.GetSection(section)
	return err == nil
}

// DeleteSection removes the named section and all config from the
// config file
func (s *HttpStorage) DeleteSection(section string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.gc.DeleteSection(section)
}

// GetSectionList returns a slice of strings with names for all the
// sections
func (s *HttpStorage) GetSectionList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.gc.GetSectionList()
}

// GetKeyList returns the keys in this section
func (s *HttpStorage) GetKeyList(section string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.gc.GetKeyList(section)
}

// GetValue returns the key in section with a found flag
func (s *HttpStorage) GetValue(section string, key string) (value string, found bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, err := s.gc.GetValue(section, key)
	if err != nil {
		return "", false
	}
	return value, true
}

// SetValue sets the value under key in section
func (s *HttpStorage) SetValue(section string, key string, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.HasPrefix(section, ":") {
		fs.Logf(nil, "Can't save config %q for on the fly backend %q", key, section)
		return
	}
	s.gc.SetValue(section, key, value)
}

// DeleteKey removes the key under section
func (s *HttpStorage) DeleteKey(section string, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.gc.DeleteKey(section, key)
}
