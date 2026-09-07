import csv

def print_data():
    with open("test", "r", encoding="utf-8") as output:
        reader = csv.DictReader(output)

        flag_string = ""
        join_flag = False

        for line in reader:
            data = line["data"]
            if data:
                if data == "H":
                    join_flag = True

                # Si el interruptor está activo (incluyendo cuando acaba de cambiar a True)
                if join_flag:
                    flag_string += data

                print(flag_string)

if __name__ == '__main__':
    print_data()
