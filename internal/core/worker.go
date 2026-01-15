package core

import (
	"sync"
)

// WorkerPool manages concurrent scanning workers
type WorkerPool struct {
	workers     int
	jobs        chan string
	results     chan *ScanResult
	engine      *Engine
	wg          sync.WaitGroup
	closed      bool
	mu          sync.Mutex
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(engine *Engine, workers int) *WorkerPool {
	return &WorkerPool{
		workers: workers,
		jobs:    make(chan string, workers*2),
		results: make(chan *ScanResult, workers*2),
		engine:  engine,
	}
}

// Start begins the worker pool
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// worker processes jobs from the queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			// Recover from panic and continue
		}
	}()

	for url := range wp.jobs {
		result, err := wp.engine.Scan(url)
		if err != nil {
			result = &ScanResult{
				URL:   url,
				Error: err,
			}
		}

		wp.mu.Lock()
		if !wp.closed {
			wp.results <- result
		}
		wp.mu.Unlock()
	}
}

// Submit adds a URL to the job queue
func (wp *WorkerPool) Submit(url string) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	
	if !wp.closed {
		wp.jobs <- url
	}
}

// Results returns the results channel
func (wp *WorkerPool) Results() <-chan *ScanResult {
	return wp.results
}

// Wait waits for all workers to complete
func (wp *WorkerPool) Wait() {
	wp.wg.Wait()
}

// Close shuts down the worker pool
func (wp *WorkerPool) Close() {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	
	if !wp.closed {
		wp.closed = true
		close(wp.jobs)
	}
}

// CloseResults closes the results channel
func (wp *WorkerPool) CloseResults() {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	
	close(wp.results)
}
