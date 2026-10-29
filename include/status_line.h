#ifndef STATUS_LINE_H_
#define STATUS_LINE_H_

#include <atomic>
#include <thread>

#include "packet_engine.h"

/// Keeps the persistent status line at the bottom of the console up to date from a background thread.
class StatusLine
{
public:
	/// Starts refreshing the status line from the engine's state. Both arguments must outlive the object.
	StatusLine(const PacketEngine& engine, const PacketEngineOptions& options);
	/// Stops the background thread if stop() was not called.
	~StatusLine();

	StatusLine(const StatusLine&)			 = delete;
	StatusLine& operator=(const StatusLine&) = delete;

	/// Stops the background thread and waits for it to finish. The status line itself is left on screen.
	void stop();

private:
	void run();

	const PacketEngine&		   engine_;
	const PacketEngineOptions& options_;
	std::atomic<bool>		   shutdown_ = false;
	std::thread				   thread_;
};

#endif
