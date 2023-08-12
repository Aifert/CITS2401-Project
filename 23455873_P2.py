"""Project 2"""

import pandas as pd
import numpy as np
from matplotlib import pyplot as plt
import time


def get_data(filename):
    """getting data"""
    data = pd.read_csv(filename)
    return data

def ecu_data(data, id):
    """give the stats for a specific id"""
    data_array = np.array(data)
    id_data = data_array[np.where(data['Arbitration_ID'] == id)]
    return id_data

def unique_id(data):
    """return the unique ids"""
    id_list = list(set(data["Arbitration_ID"]))
    id_list.sort()
    return id_list

def ecu_time_interval(data, id):
    """return the time interval of data for given id"""
    #ecu_data(data, id)[:,0])[:-1] removes the last element of the array
    result = ecu_data(data,id)[1:,0] - (ecu_data(data, id)[:,0])[:-1]
    return (result)

def ecu_summary(time_intervals):
    """return a list of the count, min, max, mean, std of time intervals of specified id"""
    data_list = np.array(["Count", "Min", "Max", "Mean", "Std"])
    stats = np.array([len(time_intervals), np.min(time_intervals), np.max(time_intervals), np.mean(time_intervals), np.std(time_intervals)])
    merge = np.vstack((data_list,stats))
    return merge

def time_interval_ceiling (interval, ceiling = 0.01):
    """given the ceiling value, convert the intervals to the nearest ceiling gap"""
    interval  = (np.floor((interval / ceiling))) * ceiling
    return interval 

def intrusion_detection(data, upper_sd = 3, lower_sd = 3, ceiling = 0.01):
    """return a (list) of detected intrusions and none intrusions"""
    detected_list = []
    benign_list = []
    up_boundary = 0
    low_boundary = 0
    for id in unique_id(data):
        time_intervals = ecu_time_interval(data, id)
        stats = ecu_summary(time_intervals)
        ecu_data_arr = ecu_data(data,id)
        up_boundary = float(stats[1][3]) + float(stats[1][4]) * upper_sd
        low_boundary = float(stats[1][3]) - float(stats[1][4]) * lower_sd
        time_interval_arr = time_interval_ceiling(time_intervals,ceiling)
        benign_list.append(ecu_data_arr[0])
        for time in enumerate(time_interval_arr):
            if low_boundary <= time[1] <= up_boundary:
                benign_list.append(ecu_data_arr[time[0]+1])
            else:
                detected_list.append(ecu_data_arr[time[0]+1])
    detected_arr = np.array(detected_list)
    benign_arr = np.array(benign_list)
    return (benign_arr), (detected_arr)

def true_analysis(data):
    """return array of real intrusions and none intrusions"""
    data_array = np.array(data)
    true_attack= data_array[np.where(data["Class"] == "Attack")]
    true_normal = data_array[np.where(data["Class"] != "Attack")]
    return true_normal,true_attack

################################################################################
#Top row left will be default values histogram
#Top row right will be customised values histogram
#Middle row left will be bar graph showing intervals and count using default ceiling value
#Middle row right will be bar graph showing intervals and count using new ceiling value
#Bottom row left will be overall performance will default up_sd, low_sd, ceiling values
#Bottom row right will be overall performance will customised up_sd, low_sd, ceiling values 
################################################################################

def attackper_ID(true_attack, id_list, data):
    """return the id with the most attack""" 
    id_attack = {}
    count = 0
    index = data.columns.get_loc('Arbitration_ID')
    for id in id_list:
        if(true_attack.size > 0):
            count = len(np.where(true_attack[:,index] == id)[0])
            id_attack[id] = count
        else:
            return -1
    return id_attack

def DLC_id(data):
    """make a dictionary to show which id has the same DLC"""
    unique_DLC = set(data['DLC'])
    data_arr = np.array(data)
    dlc_id = {}
    id_index = data.columns.get_loc('Arbitration_ID')
    for num in unique_DLC:
        index_num = np.where(data['DLC'] == num)
        id = set(data_arr[:,id_index][index_num])
        dlc_id[num] = id
    return dlc_id

def random_id(id_list):
    """return a random id"""
    n = int(np.random.randint(0,len(id_list)))
    return id_list[n]

def generate_id(data,mode):
    """generate an id based on the mode"""
    id_list = unique_id(data)
    if(mode == "max"):
        true_benign,true_attack = true_analysis(data)
        id_attack = attackper_ID(true_attack, id_list, data)
        id = max(id_attack, key=id_attack.get)
    elif(mode == "least"):
        true_benign,true_attack = true_analysis(data)
        id_attack = attackper_ID(true_attack, id_list, data)
        id = min(id_attack, key=id_attack.get)
    elif(mode == "random"):
        id = random_id(id_list)
    elif(mode == "specific"):
        id = str(input("Please give me an id:"))
        while(id not in id_list):
            id = str(input("Can't find this id in the data, try again:"))
    return id

def up_low_sd(mood, upper_sd = 3, lower_sd = 3, ceiling = 0.01):
    """user to input customised boundaries"""
    if(mood != "Yes"):
        upper_sd = float(input("Enter a customised UPPER Bound number(Integer works best):"))
        lower_sd = float(input("Enter a customised LOWER Bound number(Integer works best):"))
        ceiling = float(input("Enter a customised CEILING Number(Float works best):"))
    return upper_sd, lower_sd, ceiling

def bar_graph(data, id, upper_sd , lower_sd, ceiling):
    """graph the top graph, graph in description"""
    time_intervals = ecu_time_interval(data,id)
    time_ceiling = time_interval_ceiling(time_intervals, ceiling)
    unique_time_ceiling = list(set(time_ceiling))
    sorted(unique_time_ceiling)
    stats = ecu_summary(time_intervals)
    std, mean = float(stats[1:,4]) , float(stats[1:,3])
    up_bound, low_bound = (mean + std * upper_sd), (mean - std * lower_sd)
    within_boundary, count_per_time= [],[]
    lowcount, upcount = 0,0
    upper, lower = f">{up_bound:.4f}",f"<{low_bound:.4f}"
    for time in unique_time_ceiling:
        if(low_bound <= time <= up_bound):
            within_boundary.append(f"{time:.4f}")
            count_per_time.append(len(np.where(time_ceiling == time)[0]))
        elif(time < low_bound):
            lowcount += len(np.where(time_ceiling == time)[0])
        else:
            upcount += len(np.where(time_ceiling == time)[0])
    if(lowcount!= 0):
        plt.bar(lower, lowcount, color = 'red')
    plt.bar(within_boundary, count_per_time)
    if(upcount != 0):
        plt.bar(upper, upcount, color = 'red')
    plt.xticks(rotation = 90)
    plt.title(f"Bar Graph for Time Ceiling\nCeiling : {ceiling}\n\
              Lower Bound : {low_bound:.4f} Upper Bound : {up_bound:.4f} ")
    plt.xlabel("Time Interval")
    plt.ylabel("Number of Data")

def histogram_graph(data, id, upper_sd, lower_sd):
    """graph the middle histogram as stated in description on top"""
    time_intervals = ecu_time_interval(data,id)
    stats = ecu_summary(time_intervals)
    std, mean = float(stats[1:,4]) , float(stats[1:,3])
    num_xaxis = 250
    up_bound, low_bound = (mean + std * upper_sd), (mean - std * lower_sd)
    if(len(data) < 300000):
        num_xaxis = 100
    elif(len(data) > 600000):
        num_xaxis = 400
    plt.hist(time_intervals, bins = num_xaxis)
    plt.title(f"Histogram for ID : {id}\nUpperSD:{upper_sd} LowerSD:{lower_sd}")
    plt.xlabel("Time Interval")
    plt.ylabel("Number of Attacks")
    plt.axvline(x=low_bound, color='r', linestyle='--', label=f'Low Bound : {low_bound:.4f}')
    plt.axvline(x=up_bound, color='r', linestyle='--', label=f'Up Bound : {up_bound:.4f}')
    plt.legend()

def normal_attack_graph(data, upper_sd, lower_sd, ceiling):
    """graphs the difference between intrusion detection and the true analysis"""
    true_benign, true_attack = true_analysis(data)
    benign,detected = intrusion_detection(data, upper_sd, lower_sd, ceiling)
    x = ['Detected', 'Benign','True_Attack','True_Benign']
    y = [len(detected), len(benign), len(true_attack), len(true_benign)]
    plt.bar(x,y)
    plt.xlabel('Comparisons')
    plt.ylabel('Number of Entries')
    plt.title(f'Overall IDS Performance\nCeiling:{ceiling}')
    return(benign, detected) 

def print_id_attack_count(id_attack, filename):
    """print the number of attacks each id has"""
    for id,count in id_attack.items():
        num = 5
        if(count != 0):
            if(len(id) == 1):
                num = 7
            print(f"{id} : {count:<{num}} Number of Attacks registered")
    print(f"{filename} has a total attack count of {sum(id_attack.values())}")

def print_dlc_number(dlc_id):
    """prints the maximum and minimum dlc number in the data set and ids with it"""
    print(f"The minimum DLC number is {min(dlc_id)} and the IDs are {dlc_id[min(dlc_id)]}")
    print(f"The maximum DLC number is {max(dlc_id)} and the IDs are {dlc_id[max(dlc_id)]}")

def result_analysis(data,detected, benign):
    """analyse results and prints accuracy precision recall and f1 score"""
    index = data.columns.get_loc('Class')
    true_benign, true_attack = true_analysis(data)
    num_Dright = len(np.where(detected[:,index] == 'Attack')[0])
    num_Bright = len(np.where(benign[:,index] != 'Attack')[0])
    false_positive = len(detected) - num_Dright
    false_negative = len(benign) - num_Bright
    accuracy = (num_Dright + num_Bright) / (num_Dright + num_Bright + false_positive + false_negative)
    precision = num_Dright / len(detected)
    recall = num_Dright / len(true_attack)
    f1_score = 2 * ((precision * recall) / (precision + recall))
    print(f"{'Accuracy':<10}:{accuracy:10.4f}")
    print(f"{'Precision':<10}:{precision:10.4f}")
    print(f"{'Recall':<10}:{recall:10.4f}")
    print(f"{'F1 Score':<10}:{f1_score:10.4f}")

def generate_graph(filename):
    """generate graph for the final product"""
    data = get_data(filename)
    topL_mood = input("Do you want to use default values? (Yes or No): ")
    mode = input("Do you want to use max/least detected ID or specific ID or random ID?(max/random/least/specific): ")
    id = generate_id(data,mode)
    start = time.time()
    true_benign, true_attack = true_analysis(data)
    id_list = unique_id(data)
    id_attack = attackper_ID(true_attack, id_list, data)
    upper_sd, lower_sd, ceiling = up_low_sd(topL_mood)
    custom_upper_sd, custom_lower_sd, custom_ceiling = up_low_sd("")
    dlc_id = DLC_id(data)
    plt.subplot(3,2,1)
    histogram_graph(data, id, upper_sd, lower_sd)
    
    plt.subplot(3,2,2)
    histogram_graph(data, id, custom_upper_sd, custom_lower_sd)
    
    plt.subplot(3,2,3)
    bar_graph(data,id, upper_sd, lower_sd, ceiling)
    
    plt.subplot(3,2,4)
    bar_graph(data,id,custom_upper_sd, custom_lower_sd, custom_ceiling)
   
    plt.subplot(3,2,5)
    benign1, detected1 = normal_attack_graph(data,upper_sd, lower_sd, ceiling)
  
    plt.subplot(3,2,6)
    benign2, detected2 = normal_attack_graph(data, custom_upper_sd, custom_lower_sd,custom_ceiling)

    plt.subplots_adjust(left = 0.15, bottom = 0.11, right = 0.907, top = 0.899, wspace = 0.446, hspace = 0.994)
    print(f"Before result analysis\nUpper_SD : {upper_sd}, Lower_SD : {lower_sd}, Ceiling : {ceiling}")
    result_analysis(data, detected1, benign1)
    print(f"After result analysis\nUpper_SD : {custom_upper_sd}, Lower_SD : {custom_lower_sd}, Ceiling : {custom_ceiling}")
    result_analysis(data,detected2, benign2)
    print_id_attack_count(id_attack, filename)
    print_dlc_number(dlc_id)
    print(f"Processed {len(data)} entries of data in : {time.time() - start:.2f} seconds")
    plt.subplot_tool()
    plt.show()

if __name__ == '__main__':
    filename = input('Please give me a filename: ')
    generate_graph(filename)