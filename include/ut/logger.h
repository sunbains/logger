#pragma once

#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>
#include <syncstream>
#include <chrono>
#include <thread>
#include <string>
#include <iomanip>

namespace ut {

struct Logger {
  enum class Level {
    DEBUG,
    TRACE,
    INFO,
    WARN,
    ERROR,
    FATAL
  };

  static Logger& get_instance() noexcept {
    static Logger instance;
    return instance;
  }

  template<typename... Args>
  void log(const char* file, int line, Level level, Args&&... args) {
    auto hdr = format_header(file, line, level);

    std::ostringstream os{};

    os << hdr;

    (write(os, std::forward<Args>(args)), ...);

    std::osyncstream out{std::cerr};
    out << os.str() << "\n";
  }

  template<typename... Args>
  void debug(const char* file, int line, Args&&... args) {
    log(file, line, Level::DEBUG, std::forward<Args>(args)...);
  }
  template<typename... Args>
  void trace(const char* file, int line, Args&&... args) {
    log(file, line, Level::TRACE, std::forward<Args>(args)...);
  }

  template<typename... Args>
  void info(const char* file, int line, Args&&... args) {
    log(file, line, Level::INFO, std::forward<Args>(args)...);
  }

  template<typename... Args>
  void warn(const char* file, int line, Args&&... args) {
    log(file, line, Level::WARN, std::forward<Args>(args)...);
  }

  template<typename... Args>
  void error(const char* file, int line, Args&&... args) {
    log(file, line, Level::ERROR, std::forward<Args>(args)...);
  }

  template<typename... Args>
  void fatal(const char* file, int line, Args&&... args) {
    log(file, line, Level::FATAL, std::forward<Args>(args)...);
    abort();
  }

  Level get_level() const noexcept {
    return m_current_level;
  }

  void set_level(Level level) noexcept {
    m_current_level = level;
  }

private:
  Logger() = default;
  ~Logger() = default;
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  std::string format_header(const char* file, int line, Level level) noexcept {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    auto len = strlen(file);
    assert(len > 0);

    auto ptr = file + (len - 1);

    while (ptr != file && *ptr != '/') {
      --ptr;
    }

    assert(ptr != file && *ptr == '/');

    std::string location{ptr + 1};
    location.push_back(':');
    location.append(std::format("{}", line));

    std::ostringstream os{};

    os << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count()
       << " [" << level_to_string(level) << "] "
       << location << " "
       << std::this_thread::get_id() << " ";

    return os.str();
  }

  template<typename... Args>
  void write(std::ostream& out, Args&&... args) {
    ((out << std::forward<Args>(args)), ...);
  }

  const char* level_to_string(Level level) const {
    switch (level) {
      case Level::DEBUG: return "DBG";
      case Level::TRACE: return "TRC";
      case Level::INFO:  return "INF";
      case Level::WARN:  return "WRN";
      case Level::ERROR: return "ERR";
      case Level::FATAL: return "FTL";
      default:           return "UNK";
    }
  }

  Level m_current_level{Level::INFO};
};

} // namespace ut

#define log_level_set_debug() \
  do { \
    ut::Logger::get_instance().set_level(Logger::Level::DEBUG); \
  } while (false)

#define log_level_set_info() \
  do { \
    ut::Logger::get_instance().set_level(Logger::Level::INFO); \
  } while (false)

#define log_level_set_warn() \
  do { \
    ut::Logger::get_instance().set_level(Logger::Level::WARN); \
  } while (false)

#define log_level_set_error() \
  do { \
    ut::Logger::get_instance().set_level(Logger::Level::ERROR); \
  } while (false)

#define log_level_set_fatal() \
  do { \
    ut::Logger::get_instance().set_level(Logger::Level::FATAL); \
  } while (false)

#define log_get_level() ut::Logger::get_instance().get_level()

#define log_level_can_print(level) (log_get_level() <= level)

#define LOG(level, ...) ut::Logger::get_instance().log(__FILE__, __LINE__, ut::Logger::Level::level, __VA_ARGS__)

#define log_debug(...) \
  do { \
    if (log_level_can_print(ut::Logger::Level::DEBUG)) { \
      ut::Logger::get_instance().debug(__FILE__, __LINE__, __VA_ARGS__); \
    } \
  } while (false)

#define log_trace(...) \
  do { \
    if (log_level_can_print(ut::Logger::Level::TRACE)) { \
      ut::Logger::get_instance().trace(__FILE__, __LINE__, __VA_ARGS__); \
    } \
  } while (false)

#define log_info(...) \
  do { \
    if (log_level_can_print(ut::Logger::Level::INFO)) { \
      ut::Logger::get_instance().info(__FILE__, __LINE__, __VA_ARGS__); \
    } \
  } while (false)

#define log_warn(...) \
  do { \
    if (log_level_can_print(ut::Logger::Level::WARN)) { \
      ut::Logger::get_instance().warn(__FILE__, __LINE__, __VA_ARGS__); \
    } \
  } while (false)

#define log_error(...) \
  do { \
    if (log_level_can_print(ut::Logger::Level::ERROR)) { \
      ut::Logger::get_instance().error(__FILE__, __LINE__, __VA_ARGS__); \
    } \
  } while (false)

#define log_fatal(...) \
  do { \
    if (log_level_can_print(ut::Logger::Level::FATAL)) { \
      ut::Logger::get_instance().fatal(__FILE__, __LINE__, __VA_ARGS__); \
    } \
  } while (false)

