#include <cstdint>

#include <boost/test/unit_test.hpp>

#include "manape/work_budget.h"

BOOST_AUTO_TEST_SUITE(work_budget)

BOOST_AUTO_TEST_CASE(charges_are_exact_and_all_or_nothing)
{
	mana::detail::WorkBudget budget(3);
	BOOST_CHECK(budget.charge(2));
	BOOST_CHECK_EQUAL(budget.remaining(), 1);
	BOOST_CHECK(!budget.charge(2));
	BOOST_CHECK_EQUAL(budget.remaining(), 1);
	BOOST_CHECK(budget.charge(1));
	BOOST_CHECK_EQUAL(budget.remaining(), 0);
	BOOST_CHECK(!budget.charge(1));
}

BOOST_AUTO_TEST_CASE(charging_zero_does_not_change_the_budget)
{
	mana::detail::WorkBudget budget(3);
	BOOST_CHECK(budget.charge(0));
	BOOST_CHECK_EQUAL(budget.remaining(), 3);
}

BOOST_AUTO_TEST_CASE(maximum_charge_does_not_wrap)
{
	mana::detail::WorkBudget budget(UINT64_MAX);
	BOOST_CHECK(budget.charge(UINT64_MAX));
	BOOST_CHECK_EQUAL(budget.remaining(), 0);
	BOOST_CHECK(!budget.charge(1));
	BOOST_CHECK_EQUAL(budget.remaining(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
