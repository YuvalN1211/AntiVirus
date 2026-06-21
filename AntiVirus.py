import os

def check(path):
    list = os.listdir(path)
    global file_count, dir_count

    for item in list:
        path_item = os.path.join(path, item)
        
        if os.path.isfile(path_item):
            file_count += 1
            print(f"file path: {path_item}")
        
        else:
            dir_count += 1
            check(path_item)

file_count, dir_count = 0, 0
path = input("Enter path:\n")

check(path)

print(f"finished. Amount of files {file_count} and amount of directories {dir_count}")