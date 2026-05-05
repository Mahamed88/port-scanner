// thread pool implementation
#include "threadpool.h" 

// for each worker thread, waits for a task to be added to the queue and executes it until the thread pool is stopped
ThreadPool::ThreadPool(int numThreads) : stop(false) {
    for (int i = 0; i < numThreads; i++) {
        workers.emplace_back([this]() { 
            while (true) {
                std::function<void()> task; 

                {
                    std::unique_lock<std::mutex> lock(queueMutex); 
                    condition.wait(lock, [this]() { //
                        return stop || !tasks.empty(); // wait until there is a task to execute or the thread pool is stopped
                    });

                    if (stop && tasks.empty()) { // if the thread pool is stopped and there are no tasks left to execute, exit the thread
                        return;
                    }

                    task = tasks.front(); 
                    tasks.pop(); 
                }

                task();
            }
        });
    }
} 


void ThreadPool::enqueue(std::function<void()> task) { 
    {
        std::unique_lock<std::mutex> lock(queueMutex); 
        tasks.push(task);
    }
    condition.notify_one(); // notify one worker thread that there is a new task to execute
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        stop = true;
    }

    condition.notify_all(); 

    for (std::thread& worker : workers) {
        worker.join();
    }
}