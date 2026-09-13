# RedFlag – The Fraud Files 🚩

## SQL-Based Fraud Detection Engine

RedFlag is a pure SQL fraud detection project designed to identify suspicious transaction patterns in a large financial transaction dataset.

The project focuses on detecting potentially fraudulent behavior using SQL queries, CTEs, aggregations, window functions, and time-based analysis.

## 🎯 Project Objective

The objective of RedFlag is to build a SQL-based fraud detection engine capable of identifying suspicious transaction behavior without using Machine Learning, Python, or external APIs.

## 🔍 Fraud Patterns Detected

The project analyzes 12 different fraud patterns:

1. Velocity – unusually high daily transaction activity
2. Round-Amount Transactions
3. Card Testing – repeated small-value transactions
4. Failed-Then-Succeeded Transactions
5. Odd-Hour Transaction Activity
6. Mule Account Behavior
7. Refund Abuse
8. Merchant Collusion
9. Just-Under-Threshold Transactions
10. Dormant-Then-Active Accounts
11. Velocity Spike
12. Rapid Geographic Shift

## 🛠️ Technologies Used

- MySQL
- SQL
- Common Table Expressions (CTEs)
- Window Functions
- Aggregate Functions
- Date & Time Functions
- CASE Statements
- Subqueries

## 📊 Dataset

The project uses a large transaction dataset containing approximately 200,000 transaction records and around 14,700 users.

The dataset contains information such as:

- Transaction ID
- User ID
- Merchant ID
- Transaction Amount
- Transaction Time
- Transaction Status
- Payment Mode
- City
- Transaction Type

## 💡 Key Learning Outcomes

Through this project, I practiced:

- Writing complex SQL queries
- Using CTEs for multi-step analysis
- Applying window functions such as LAG() and ROW_NUMBER()
- Performing fraud-pattern analysis
- Working with date and time calculations
- Aggregating transaction-level data
- Translating real-world fraud scenarios into SQL logic

## 📁 Project Structure

RedFlag/
│
├── RedFlag_RutuShah.sql
├── README.md
└── screenshots/
    ├── output1.png
    ├── output2.png
    ├── output3.png
    └── output4.png

## 🚩 Conclusion

RedFlag demonstrates how SQL can be used as a powerful fraud detection tool by converting real-world suspicious behavior into measurable transaction patterns.

This project strengthened my understanding of SQL analytics and showed how database-level analysis can support financial fraud monitoring.

