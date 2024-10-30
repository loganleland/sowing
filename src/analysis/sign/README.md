# Sign Analysis

This analysis implements the following Hasse Diagram

```mermaid
  graph TD;
    T -- negZero[<=0];
    T -- nonZero[!=0];
    T -- posZero[>=0];

    nonZero -- neg[<0];
    nonZero -- pos[>0];

    negZero -- eqZero[=0];
    negZero -- neg;

    posZero -- eqZero;
    posZero -- pos;

    neg -- Bottom[⊥];
    eqZero -- Bottom;
    pos -- Bottom;
```

## Detections
### Memory
The following memory alarms are implemented:
- ```void *malloc(size_t size)```:
  - size is 0 or <0 input
- ```void* calloc(size_t num, size_t size)```:
  - size is 0 or <0 input
- ```void *aligned_alloc(size_t alignment, size_t size)```:
  - size or alignment is 0 or <0
- ```void *realloc(void *ptr, size_t new_size)```:
  - new_size is 0 or <0 input
- ```void free_sized(void* ptr, size_t size)```
  - with 0 or <0 input

### String
- ```char* strncpy(char * destination, const char * source, size_t num)```:
  - num is 0 or <0 size parameter
- ```char* strncat(char* dest, const char* src, std::size_t count)```:
  - count is 0 or <0
- ```int strncmp(const char * str1, const char * str2, size_t num)```:
  - num is 0 or <0
- ```int wcsncmp(const wchar_t* lhs, const wchar_t* rhs, std::size_t count)```:
  - count is 0 or <0

### C++ Container
- ```void vector::resize(size_type count)```
  - count is <0
- ```void vector::reserve(size_type new_cap)```
  - new_cap is 0 or <0
- ```void deque::resize(size_type count)```
  - count is 0 or <0
- ```void forward_list::resize(size_type count)```
  - count is 0 or <0 
