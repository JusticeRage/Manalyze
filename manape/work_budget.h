#pragma once

#include <cstdint>

namespace mana::detail {

class WorkBudget
{
public:
	explicit constexpr WorkBudget(std::uint64_t limit) noexcept : _remaining(limit) {}

	bool charge(std::uint64_t amount) noexcept
	{
		if (amount > _remaining) return false;
		_remaining -= amount;
		return true;
	}

	constexpr std::uint64_t remaining() const noexcept { return _remaining; }

private:
	std::uint64_t _remaining;
};

} // namespace mana::detail
