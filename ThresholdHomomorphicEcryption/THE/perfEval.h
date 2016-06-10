#ifndef PERF_EVAL_H
#define PERF_EVAL_H

#include <iostream>
#include <chrono>

class Timer{
	public:
		Timer(): start_(clock_::now()){}
		void reset(){
			start_ = clock_::now();
		}
		double elapsed() const{
			return std::chrono::duration_cast<second_>(clock_::now() - start_).count();
		}
	private:
		typedef std::chrono::high_resolution_clock clock_;
		typedef std::chrono::duration<double, std::ratio<1>> second_;
		std::chrono::time_point<clock_> start_;
};
#endif // PERF_EVAL_H
