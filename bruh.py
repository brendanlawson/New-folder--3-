import csv

def generate_financial_plan_csv(filename="Bang_Tinh_Dong_Tien.csv"):
    weekly_debt_deduction = 264004
    fixed_gas = 70000

    debt_schedule = {
        4: 944622,
        8: 1110238,
        12: 1113187
    }

    incomes = [500000, 700000, 500000, 700000, 500000, 700000, 
               500000, 600000, 500000, 700000, 600000, 700000]

    header = [
        "Tuần", "Thu nhập", "Tiền xăng", 
        "Trích quỹ nợ", "Rút quỹ dự phòng", 
        "Tiền ăn", "Thanh toán", 
        "Quỹ dự phòng", "Quỹ nợ"
    ]

    rows = []

    # Dòng ban đầu (row 2 trong Excel)
    rows.append([
        "Số dư ban đầu", "", "", "", "", "", "",
        471001, 0
    ])

    for i, income in enumerate(incomes):
        row_index = i + 3  # vì Excel bắt đầu từ dòng 1 (header) + dòng 2 (initial)

        payment = debt_schedule.get(i + 1, 0)

        # Công thức Excel
        reserve_formula = f"=H{row_index-1}-E{row_index}"
        debt_formula = f"=I{row_index-1}+D{row_index}-G{row_index}"

        buffer_formula = f"=IF(B{row_index}<600000,MIN(100000,H{row_index-1}),0)"
        food_formula = f"=B{row_index}-C{row_index}-D{row_index}+E{row_index}"

        rows.append([
            f"Tuần {i+1}",
            income,
            fixed_gas,
            weekly_debt_deduction,
            buffer_formula,
            food_formula,
            payment,
            reserve_formula,
            debt_formula
        ])

    with open(filename, mode='w', encoding='utf-8-sig', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(rows)

    print("Đã tạo file CSV với công thức Excel.")

if __name__ == "__main__":
    generate_financial_plan_csv()