

total_supply_at_hard_fork = 0 # to be supplied

hardfork_number = 4730666
halving_interval = 3000000   # 2628000 ~ 1 year, assume 10 ~ 15 seconds for each block
block_reward = 8 * 1000000000000000000   # in unit of wei


total_supply = 0

for interval in range(1, 65):

    each_block_reward = block_reward >> interval
    rewards_in_this_interval = each_block_reward * halving_interval
    total_supply = total_supply + rewards_in_this_interval

    print("interval {}: each block reward: {} total rewards in this reward: {} sum till now: {}".format(interval, each_block_reward, rewards_in_this_interval, total_supply))

    
total_supply = (total_supply + total_supply_at_hard_fork) / 1000000000000000000

print("total supply: {} eth".format(total_supply))

