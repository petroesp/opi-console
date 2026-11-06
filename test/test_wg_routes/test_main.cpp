#include <unity.h>

#include "../../src/wg_routes.h"

void testParsesIpv4CidrAndMatchesAddresses() {
  wg_routes::Route route = {};
  TEST_ASSERT_TRUE(wg_routes::parseIpv4Cidr("10.20.30.0/24", route));
  TEST_ASSERT_EQUAL_UINT32(0x0A141E00u, route.network);
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFF00u, route.mask);
  TEST_ASSERT_TRUE(wg_routes::matches(route, 0x0A141E45u));
  TEST_ASSERT_FALSE(wg_routes::matches(route, 0x0A141F01u));
}

void testRejectsMalformedAndUnsupportedPrefixes() {
  wg_routes::Route route = {};
  TEST_ASSERT_FALSE(wg_routes::parseIpv4Cidr("10.20.300.1/24", route));
  TEST_ASSERT_FALSE(wg_routes::parseIpv4Cidr("10.20.30.1/33", route));
  TEST_ASSERT_FALSE(wg_routes::parseIpv4Cidr("10.20.30.1/24junk", route));
  TEST_ASSERT_FALSE(wg_routes::parseIpv4Cidr("10.20.30/24", route));
}

void testSelectsMostSpecificMatchingRoute() {
  wg_routes::Route routes[3] = {};
  size_t owners[3] = {0, 1, 2};
  TEST_ASSERT_TRUE(wg_routes::parseIpv4Cidr("0.0.0.0/0", routes[0]));
  TEST_ASSERT_TRUE(wg_routes::parseIpv4Cidr("10.0.0.0/8", routes[1]));
  TEST_ASSERT_TRUE(wg_routes::parseIpv4Cidr("10.20.0.0/16", routes[2]));

  TEST_ASSERT_EQUAL_INT(2, wg_routes::bestMatch(routes, owners, 3, 0x0A140102u));
  TEST_ASSERT_EQUAL_INT(1, wg_routes::bestMatch(routes, owners, 3, 0x0A010203u));
  TEST_ASSERT_EQUAL_INT(0, wg_routes::bestMatch(routes, owners, 3, 0xC0000201u));
}

void testDetectsOverlappingNetworks() {
  wg_routes::Route wider = {}, narrower = {}, separate = {};
  TEST_ASSERT_TRUE(wg_routes::parseIpv4Cidr("10.0.0.0/8", wider));
  TEST_ASSERT_TRUE(wg_routes::parseIpv4Cidr("10.12.0.0/16", narrower));
  TEST_ASSERT_TRUE(wg_routes::parseIpv4Cidr("192.168.0.0/16", separate));
  TEST_ASSERT_TRUE(wg_routes::overlaps(wider, narrower));
  TEST_ASSERT_FALSE(wg_routes::overlaps(wider, separate));
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(testParsesIpv4CidrAndMatchesAddresses);
  RUN_TEST(testRejectsMalformedAndUnsupportedPrefixes);
  RUN_TEST(testSelectsMostSpecificMatchingRoute);
  RUN_TEST(testDetectsOverlappingNetworks);
  return UNITY_END();
}
