package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"time"

	"golang.org/x/mod/semver"
)

const checkForUpdatesInterval = 24 * time.Hour

type UpdateInfo struct {
	CurrentVersion string
	LatestVersion  string
}

func IsUpdateAvailable(ctx context.Context, currentVersion string) (*UpdateInfo, error) {
	latestVersion, err := getLatestVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get latest version: %w", err)
	}

	if semver.Compare(latestVersion, currentVersion) > 0 {
		return &UpdateInfo{
			CurrentVersion: currentVersion,
			LatestVersion:  latestVersion,
		}, nil
	}

	return nil, nil
}

func getLatestVersion(ctx context.Context) (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("could not get cache dir: %w", err)
	}

	latestVersionPath := path.Join(cacheDir, "kubectl-request-version.txt")
	fi, err := os.Stat(latestVersionPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("coult not access version file: %w", err)
	}

	if fi != nil && fi.ModTime().After(time.Now().Add(-checkForUpdatesInterval)) {
		latestVersion, err := os.ReadFile(latestVersionPath)
		if err != nil {
			return "", fmt.Errorf("could not read version info: %w", err)
		}

		return string(latestVersion), nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/spreadshirt/kube-request-access/releases/latest", nil)
	if err != nil {
		return "", fmt.Errorf("could not create request: %w", err)
	}

	req.Header.Set("User-Agent", "kubectl-request / https://github.com/spreadshirt/kube-request-access")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("expected status code %d but got %d: %q", http.StatusOK, resp.StatusCode, data)
	}

	var releaseInfo struct {
		TagName string `json:"tag_name"`
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&releaseInfo)
	if err != nil {
		return "", fmt.Errorf("could not parse release info: %w", err)
	}

	if releaseInfo.TagName == "" {
		return "", fmt.Errorf("could not determine release version, maybe the GitHub API changed?")
	}

	err = os.WriteFile(latestVersionPath, []byte(releaseInfo.TagName), 0644)
	if err != nil {
		return "", fmt.Errorf("could not cache release info: %w", err)
	}

	return releaseInfo.TagName, nil
}
