/*
 *
 * Copyright 2017 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef ASYLO_TEST_UTIL_STATUS_MATCHERS_H_
#define ASYLO_TEST_UTIL_STATUS_MATCHERS_H_

#include <memory>
#include <string>

#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace internal {

// Implements a gMock matcher that checks that an asylo::StaturOr<T> has an OK
// status and that the contained T value matches another matcher.
template <typename T>
class IsOkAndHoldsMatcher
    : public ::testing::MatcherInterface<const StatusOr<T> &> {
 public:
  template <typename MatcherT>
  IsOkAndHoldsMatcher(MatcherT &&value_matcher)
      : value_matcher_(::testing::SafeMatcherCast<const T &>(value_matcher)) {}

  // From testing::MatcherInterface.
  void DescribeTo(std::ostream *os) const override {
    *os << "is OK and contains a value that ";
    value_matcher_.DescribeTo(os);
  }

  // From testing::MatcherInterface.
  void DescribeNegationTo(std::ostream *os) const override {
    *os << "is not OK or contains a value that ";
    value_matcher_.DescribeNegationTo(os);
  }

  // From testing::MatcherInterface.
  bool MatchAndExplain(
      const StatusOr<T> &status_or,
      ::testing::MatchResultListener *listener) const override {
    if (!status_or.ok()) {
      *listener << "which is not OK";
      return false;
    }

    ::testing::StringMatchResultListener value_listener;
    bool is_a_match =
        value_matcher_.MatchAndExplain(status_or.ValueOrDie(), &value_listener);
    std::string value_explanation = value_listener.str();
    if (!value_explanation.empty()) {
      *listener << absl::StrCat("which contains a value ", value_explanation);
    }

    return is_a_match;
  }

 private:
  const ::testing::Matcher<const T &> value_matcher_;
};

// A polymorphic IsOkAndHolds() matcher.
//
// IsOkAndHolds() returns a matcher that can be used to process an IsOkAndHolds
// expectation. However, the value type T is not provided when IsOkAndHolds() is
// invoked. The value type is only inferable when the gtest framework invokes
// the matcher with a value. Consequently, the IsOkAndHolds() function must
// return an object that is implicitly convertible to a matcher for StatusOr<T>.
// gtest refers to such an object as a polymorphic matcher, since it can be used
// to match with more than one type of value.
template <typename ValueMatcherT>
class IsOkAndHoldsGenerator {
 public:
  explicit IsOkAndHoldsGenerator(ValueMatcherT value_matcher)
      : value_matcher_(std::move(value_matcher)) {}

  template <typename T>
  operator ::testing::Matcher<const StatusOr<T> &>() const {
    return ::testing::MakeMatcher(new IsOkAndHoldsMatcher<T>(value_matcher_));
  }

 private:
  const ValueMatcherT value_matcher_;
};

// Implements a polymorphic matcher for checking expectations on Status-like
// objects.
template <typename Enum>
class StatusMatcher {
 public:
  template <typename MessageMatcherT>
  StatusMatcher(Enum code, MessageMatcherT message_matcher)
      : code_(code),
        message_matcher_(
            ::testing::SafeMatcherCast<const std::string &>(message_matcher)),
        error_space_(error::error_enum_traits<Enum>::get_error_space()) {}

  // Required by testing::MakePolymorphicMatcher
  //
  // Describes the expected error code and message constraints.
  void DescribeTo(std::ostream *os) const {
    *os << "has error code " << error_space_->SpaceName()
        << "::" << error_space_->String(static_cast<int>(code_))
        << " and a message that ";
    message_matcher_.DescribeTo(os);
  }

  // Required by testing::MakePolymorphicMatcher
  //
  // Describes the status not matching the expected error code and message
  // constraints.
  void DescribeNegationTo(std::ostream *os) const {
    *os << "does not match expected error space" << error_space_->SpaceName()
        << ", or does not match error code "
        << error_space_->String(static_cast<int>(code_))
        << ", or does not have an error message that ";
    message_matcher_.DescribeNegationTo(os);
  }

  // Required by testing::MakePolymorphicMatcher
  //
  // Tests whether |status_like| has an error code and error message that meet
  // this matcher's expectations.
  template <typename T>
  bool MatchAndExplain(const T &status_like,
                       ::testing::MatchResultListener *listener) const {
    Status status = GetStatus(status_like);
    if (!status.Is(code_)) {
      *listener << "whose error code is " << status.error_space()->SpaceName()
                << "::" << status.error_space()->String(status.error_code());
      return false;
    }
    ::testing::StringMatchResultListener string_listener;
    if (!message_matcher_.MatchAndExplain(std::string(status.error_message()),
                                          &string_listener)) {
      std::string explanation = string_listener.str();
      *listener << "which has an error message "
                << (explanation.empty() ? "which does not match the expectation"
                                        : explanation);
      return false;
    }
    return true;
  }

 private:
  template <typename ValueT>
  static Status GetStatus(const StatusOr<ValueT> &status_or) {
    return status_or.status();
  }

  static Status GetStatus(const Status &status) { return status; }

  // To extend this type to support additional types, add a new GetStatus
  // implementation that accepts the type which can be converted to a Status
  // object for comparison by MatchAndExplain.

  // Expected error code.
  const Enum code_;

  // Error message matcher.
  const ::testing::Matcher<const std::string &> message_matcher_;

  // Error space of the expected error code.
  const error::ErrorSpace *const error_space_;
};

// Implements a gMock matcher that checks whether a status container (e.g.
// asylo::Status or asylo::StatusOr<T>) has an OK status.
class IsOkMatcher {
 public:
  IsOkMatcher() = default;

  // Describes the OK expectation.
  void DescribeTo(std::ostream *os) const { *os << "is OK"; }

  // Describes the negative OK expectation.
  void DescribeNegationTo(std::ostream *os) const { *os << "is not OK"; }

  // Tests whether |status_container|'s OK value meets this matcher's
  // expectation.
  template <class T>
  bool MatchAndExplain(const T &status_container,
                       ::testing::MatchResultListener *listener) const {
    if (!status_container.ok()) {
      *listener << "which is not OK";
      return false;
    }
    return true;
  }
};

}  // namespace internal

// Returns a gMock matcher that expects an asylo::StatusOr<T> object to have an
// OK status and for the contained T object to match |value_matcher|.
//
// Example:
//
//     StatusOr<string> raven_speech_result = raven.Speak();
//     EXPECT_THAT(raven_speech_result, IsOkAndHolds(HasSubstr("nevermore")));
//
// If foo is an object of type T and foo_result is an object of type
// StatusOr<T>, you can write:
//
//     EXPECT_THAT(foo_result, IsOkAndHolds(foo));
//
// instead of:
//
//     EXPECT_THAT(foo_result, IsOkAndHolds(Eq(foo)));
template <typename ValueMatcherT>
internal::IsOkAndHoldsGenerator<ValueMatcherT> IsOkAndHolds(
    ValueMatcherT value_matcher) {
  return internal::IsOkAndHoldsGenerator<ValueMatcherT>(value_matcher);
}

// Returns a gMock matcher that expects an asylo::Status object to have the
// given |code|.
template <typename Enum>
::testing::PolymorphicMatcher<internal::StatusMatcher<Enum>> StatusIs(
    Enum code) {
  return ::testing::MakePolymorphicMatcher(
      internal::StatusMatcher<Enum>(code, ::testing::_));
}

// Returns a gMock matcher that expects an asylo::Status object to have the
// given |code| and an error message matching |message_matcher|.
template <typename Enum, typename MessageMatcherT>
::testing::PolymorphicMatcher<internal::StatusMatcher<Enum>> StatusIs(
    Enum code, MessageMatcherT message_matcher) {
  return ::testing::MakePolymorphicMatcher(
      internal::StatusMatcher<Enum>(code, message_matcher));
}

// Returns an internal::IsOkMatcherGenerator, which may be typecast to a
// Matcher<asylo::Status> or Matcher<asylo::StatusOr<T>>. These gMock
// matchers test that a given status container has an OK status.
inline ::testing::PolymorphicMatcher<internal::IsOkMatcher> IsOk() {
  return ::testing::MakePolymorphicMatcher(internal::IsOkMatcher());
}

// Macros for testing the results of functions that return asylo::Status or
// asylo::StatusOr<T> (for any type T).
#define ASYLO_EXPECT_OK(rexpr) EXPECT_THAT(rexpr, ::asylo::IsOk())
#define ASYLO_ASSERT_OK(rexpr) ASSERT_THAT(rexpr, ::asylo::IsOk())

// Executes an expression that returns an asylo::StatusOr<T>, and assigns the
// contained variable to lhs if the error code is OK.
// If the Status is non-OK, generates a test failure and returns from the
// current function, which must have a void return type.
//
// Example: Assigning to an existing value
//   ValueType value;
//   ASYLO_ASSERT_OK_AND_ASSIGN(value, MaybeGetValue(arg));
//
// The value assignment example might expand into:
//   StatusOr<ValueType> status_or_value = MaybeGetValue(arg);
//   ASYLO_ASSERT_OK(status_or_value.status());
//   value = status_or_value.ValueOrDie();
#define ASYLO_ASSERT_OK_AND_ASSIGN(lhs, rexpr)                           \
  do {                                                                   \
    auto _asylo_status_to_verify = rexpr;                                \
    if (!_asylo_status_to_verify.ok()) {                                 \
      FAIL() << #rexpr                                                   \
             << " returned error: " << _asylo_status_to_verify.status(); \
    }                                                                    \
    lhs = std::move(_asylo_status_to_verify).ValueOrDie();               \
  } while (false)

// Implements the PrintTo() method for asylo::StatusOr<T>. This method is
// used by gtest to print asylo::StatusOr<T> objects for debugging. The
// implementation relies on gtest for printing values of T when a
// asylo::StatusOr<T> object is OK and contains a value.
template <typename T>
void PrintTo(const StatusOr<T> &statusor, std::ostream *os) {
  if (!statusor.ok()) {
    *os << statusor.status();
  } else {
    *os << absl::StrCat("OK: ",
                        ::testing::PrintToString(statusor.ValueOrDie()));
  }
}

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_STATUS_MATCHERS_H_
