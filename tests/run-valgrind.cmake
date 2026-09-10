cmake_minimum_required(VERSION 3.21)

# Local CTest dashboard: collect MemCheck logs without submitting anything.
get_filename_component(CTEST_SOURCE_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
if(NOT DIRECTGATE_VALGRIND_BUILD_DIR)
    message(FATAL_ERROR "DIRECTGATE_VALGRIND_BUILD_DIR is required; use tests/run-valgrind.sh")
endif()
get_filename_component(CTEST_BINARY_DIRECTORY "${DIRECTGATE_VALGRIND_BUILD_DIR}" ABSOLUTE)
if(NOT EXISTS "${CTEST_BINARY_DIRECTORY}/CTestTestfile.cmake")
    message(FATAL_ERROR "No configured tests in ${CTEST_BINARY_DIRECTORY}")
endif()

set(CTEST_SITE "local")
set(CTEST_BUILD_NAME "directgate-valgrind")
set(CTEST_MEMORYCHECK_TYPE "Valgrind")
find_program(CTEST_MEMORYCHECK_COMMAND valgrind REQUIRED)
set(CTEST_MEMORYCHECK_COMMAND_OPTIONS
    "--leak-check=full --show-leak-kinds=definite,indirect,possible --errors-for-leak-kinds=definite,indirect,possible --track-origins=yes --error-exitcode=1")
set(CTEST_MEMORYCHECK_SUPPRESSIONS_FILE "${CMAKE_CURRENT_LIST_DIR}/valgrind.supp")

ctest_start(Experimental)
ctest_memcheck(RETURN_VALUE test_result DEFECT_COUNT defects)
# Check both: a test may return success while Valgrind reports errors from a
# forked child, or return a skip code despite a memory error in its log.
if(NOT test_result EQUAL 0 OR NOT defects EQUAL 0)
    message(FATAL_ERROR
        "Valgrind failed: test result ${test_result}, memory defects ${defects}. See ${CTEST_BINARY_DIRECTORY}/Testing/Temporary/MemoryChecker.*.log")
endif()
