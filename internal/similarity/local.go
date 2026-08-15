package similarity

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bluezly/CIRadar/internal/config"
	"github.com/Bluezly/CIRadar/internal/httpguard"
)

type wordVectorModel struct {
	Dimensions int
	Vectors    map[string][]float64
}

var vectorModelCache = struct {
	sync.Mutex
	models map[string]*wordVectorModel
}{models: map[string]*wordVectorModel{}}

func localVectorEmbeddings(path string, input []string) ([][]float64, error) {
	model, err := loadWordVectors(path)
	if err != nil {
		return nil, err
	}
	out := make([][]float64, len(input))
	for i, value := range input {
		out[i] = model.sentence(value)
	}
	return out, nil
}

func loadWordVectors(path string) (*wordVectorModel, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("local vector path is empty")
	}
	vectorModelCache.Lock()
	if cached := vectorModelCache.models[path]; cached != nil {
		vectorModelCache.Unlock()
		return cached, nil
	}
	vectorModelCache.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 128<<10), 8<<20)
	vectors := map[string][]float64{}
	dimensions := 0
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		fields := strings.Fields(scanner.Text())
		if lineNumber == 1 && len(fields) == 2 {
			if _, errCount := strconv.Atoi(fields[0]); errCount == nil {
				if dim, errDim := strconv.Atoi(fields[1]); errDim == nil && dim > 0 {
					dimensions = dim
					continue
				}
			}
		}
		if len(fields) < 3 {
			continue
		}
		if dimensions == 0 {
			dimensions = len(fields) - 1
		}
		if len(fields)-1 != dimensions {
			continue
		}
		vectorValue := make([]float64, dimensions)
		valid := true
		for i := 0; i < dimensions; i++ {
			n, parseErr := strconv.ParseFloat(fields[i+1], 64)
			if parseErr != nil {
				valid = false
				break
			}
			vectorValue[i] = n
		}
		if valid {
			normalizeVector(vectorValue)
			vectors[strings.ToLower(fields[0])] = vectorValue
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if dimensions < 8 || len(vectors) < 2 {
		return nil, errors.New("local vector model is empty or invalid")
	}
	model := &wordVectorModel{Dimensions: dimensions, Vectors: vectors}
	vectorModelCache.Lock()
	vectorModelCache.models[path] = model
	vectorModelCache.Unlock()
	return model, nil
}

func (m *wordVectorModel) sentence(value string) []float64 {
	result := make([]float64, m.Dimensions)
	weightTotal := 0.0
	for _, token := range tokenize(value) {
		vectorValue := m.Vectors[token]
		if len(vectorValue) == 0 {
			vectorValue = m.Vectors[strings.Trim(token, "-_0123456789")]
		}
		if len(vectorValue) == 0 {
			continue
		}
		weight := 1 / math.Sqrt(1+float64(len(token)))
		for i, n := range vectorValue {
			result[i] += n * weight
		}
		weightTotal += weight
	}
	if weightTotal > 0 {
		for i := range result {
			result[i] /= weightTotal
		}
		normalizeVector(result)
	}
	return result
}

func ollamaEmbeddings(ctx context.Context, semantic config.SemanticConfig, input []string) ([][]float64, error) {
	payload, err := json.Marshal(map[string]any{"model": semantic.LocalModel, "input": input, "truncate": true})
	if err != nil {
		return nil, err
	}
	client := httpguard.NewClient(60*time.Second, true)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, semantic.LocalEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if semantic.LocalAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+semantic.LocalAPIKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp.Body, 32<<20)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("local embedding HTTP %d", resp.StatusCode)
	}
	var output struct {
		Embeddings [][]float64 `json:"embeddings"`
	}
	if err := json.Unmarshal(body, &output); err != nil {
		return nil, err
	}
	if len(output.Embeddings) != len(input) {
		return nil, errors.New("local embedding response has an unexpected vector count")
	}
	for _, vectorValue := range output.Embeddings {
		if len(vectorValue) == 0 {
			return nil, errors.New("local embedding response contains an empty vector")
		}
		normalizeVector(vectorValue)
	}
	return output.Embeddings, nil
}

func normalizeVector(vectorValue []float64) {
	normValue := 0.0
	for _, value := range vectorValue {
		normValue += value * value
	}
	if normValue == 0 {
		return
	}
	normValue = math.Sqrt(normValue)
	for i := range vectorValue {
		vectorValue[i] /= normValue
	}
}
