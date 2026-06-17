#include "hello.h"

#include "beacon.h"

void print_hello() {
  BeaconPrintf(CALLBACK_OUTPUT, "Hello world\n");
}
