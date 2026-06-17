/*
 * Partial beacon.h header file for using the Beacon API.
 *
 * https://github.com/Cobalt-Strike/bof-vs/blob/main/BOF-Template/beacon.h
 */

#ifndef BEACON_H
#define BEACON_H

#ifdef __cplusplus
extern "C" {
#endif

#define CALLBACK_OUTPUT 0

__declspec(dllimport) void BeaconPrintf(int, const char *, ...);

#ifdef __cplusplus
};
#endif

#endif /* BEACON_H */
