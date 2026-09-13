-- =====================================================================
-- RedFlag — Fraud Detection Submission
-- Student: Rutu Shah | Batch: DA-DS-1
-- =====================================================================

USE redflag;
-- =====================================================================
-- P1: Velocity Fraud
-- Detect users making 30 or more transactions on a single calendar day.
-- Looking for unusually high transaction activity concentrated in one day.
-- =====================================================================

SELECT
    user_id,
    DATE(txn_time) AS transaction_date,
    COUNT(*) AS daily_transaction_count
FROM transactions
GROUP BY
    user_id,
    DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY
    daily_transaction_count DESC;

-- Findings:
-- Suspect count: 50 user-days
-- Examples: See the query result for the highest daily transaction counts.

-- =====================================================================
-- P2: Round-Amount Clustering
-- Detect users making 15 or more transactions using common round amounts.
-- Looking for repeated use of suspiciously standardized transaction values.
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS round_amount_transactions
FROM transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY
    user_id
HAVING COUNT(*) >= 15
ORDER BY
    round_amount_transactions DESC;
-- Findings:
-- Suspect count: 25 users
-- Examples: See the query result for users with the highest
-- round-amount transaction counts.

-- =====================================================================
-- P3: Card Testing
-- Detect users making 30 or more transactions under ₹10 on one day.
-- Looking for repeated small-value transactions that may indicate
-- card or payment-method testing.
-- =====================================================================

SELECT
    user_id,
    DATE(txn_time) AS transaction_date,
    COUNT(*) AS small_transaction_count
FROM transactions
WHERE amount < 10
GROUP BY
    user_id,
    DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY
    small_transaction_count DESC;
-- Findings:
-- Suspect count: 20 user-days
-- Examples: See the query result for users with the highest
-- number of small-value transactions.

-- =====================================================================
-- P4: Failed-Then-Succeeded
-- Detect users with 20 or more failed transactions.
-- Looking for repeated payment failures that may indicate suspicious
-- payment attempts or transaction testing.
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS failed_transaction_count
FROM transactions
WHERE status = 'FAILED'
GROUP BY
    user_id
HAVING COUNT(*) >= 20
ORDER BY
    failed_transaction_count DESC;
    -- Findings:
-- Suspect count: 25 users
-- Examples: See the query result for users with the highest
-- number of failed transactions.

-- =====================================================================
-- P5: Odd-Hour Concentration
-- Detect users with at least 30 total transactions where 80% or more
-- occur between 2 AM and 5 AM (hours 2, 3, and 4).
-- Looking for unusually concentrated activity during odd hours.
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN HOUR(txn_time) BETWEEN 2 AND 4
            THEN 1
            ELSE 0
        END
    ) AS odd_hour_transactions,
    ROUND(
        100.0 * SUM(
            CASE
                WHEN HOUR(txn_time) BETWEEN 2 AND 4
                THEN 1
                ELSE 0
            END
        ) / COUNT(*),
        2
    ) AS odd_hour_percentage
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 30
   AND odd_hour_percentage >= 80
ORDER BY odd_hour_percentage DESC;

-- Findings:
-- Suspect count: 20 users
-- Examples: See the query result for users with the highest
-- odd-hour transaction percentages.

-- =====================================================================
-- P6: Mule Accounts
-- Detect users with 8 or more CREDIT transactions.
-- Looking for accounts receiving repeated credit transactions that
-- may indicate mule-account activity.
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS credit_transaction_count
FROM transactions
WHERE txn_type = 'CREDIT'
GROUP BY user_id
HAVING COUNT(*) >= 8
ORDER BY credit_transaction_count DESC;
-- Findings:
-- Suspect count: 30 users
-- Examples: See the query result for users with the highest
-- number of CREDIT transactions.

-- =====================================================================
-- P7: Refund Abuse
-- Detect users with at least 20 transactions and a refund ratio
-- greater than 40%.
-- Looking for unusually high refund activity compared with total
-- transaction activity.
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN txn_type = 'REFUND'
            THEN 1
            ELSE 0
        END
    ) AS refund_transactions,
    ROUND(
        100.0 * SUM(
            CASE
                WHEN txn_type = 'REFUND'
                THEN 1
                ELSE 0
            END
        ) / COUNT(*),
        2
    ) AS refund_percentage
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 20
   AND refund_percentage > 40
ORDER BY refund_percentage DESC;

-- Findings:
-- Suspect count: 24 users
-- Examples: See the query result for users with the highest
-- refund percentages.
-- =====================================================================
-- P8: Merchant Collusion
-- Detect merchants where the top 5 users by transaction value account
-- for more than 60% of the merchant's total transaction value.
-- Looking for suspicious concentration of activity among a small
-- group of users.
-- =====================================================================

WITH user_merchant_totals AS (
    SELECT
        merchant_id,
        user_id,
        SUM(amount) AS user_total
    FROM transactions
    GROUP BY
        merchant_id,
        user_id
),
ranked_users AS (
    SELECT
        merchant_id,
        user_id,
        user_total,
        ROW_NUMBER() OVER (
            PARTITION BY merchant_id
            ORDER BY user_total DESC
        ) AS user_rank
    FROM user_merchant_totals
),
merchant_totals AS (
    SELECT
        merchant_id,
        SUM(amount) AS merchant_total
    FROM transactions
    GROUP BY merchant_id
),
top_five_totals AS (
    SELECT
        merchant_id,
        SUM(user_total) AS top_five_total
    FROM ranked_users
    WHERE user_rank <= 5
    GROUP BY merchant_id
)
SELECT
    t.merchant_id,
    t.top_five_total,
    m.merchant_total,
    ROUND(
        100.0 * t.top_five_total / m.merchant_total,
        2
    ) AS top_five_percentage
FROM top_five_totals t
JOIN merchant_totals m
    ON t.merchant_id = m.merchant_id
WHERE t.top_five_total / m.merchant_total > 0.60
ORDER BY top_five_percentage DESC;

-- Findings:
-- Suspect count: 15 merchants
-- Examples: See the query result for merchants with the highest
-- top-five transaction-value concentration.

-- =====================================================================
-- P9: Just-Under-Threshold
-- Detect users with 10 or more transactions of exactly ₹9,999.
-- Looking for repeated transactions just below a common transaction
-- threshold.
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS threshold_transactions
FROM transactions
WHERE amount = 9999.00
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY threshold_transactions DESC;
-- Findings:
-- Suspect count: 20 users
-- Examples: See the query result for users with the highest
-- number of ₹9,999 transactions.

-- =====================================================================
-- P10: Dormant-Then-Active
-- Detect users with a gap of at least 90 days between consecutive
-- transactions, followed by at least 15 transactions after the gap.
-- Looking for previously dormant accounts that suddenly become active.
-- =====================================================================

WITH transaction_gaps AS (
    SELECT
        user_id,
        txn_time,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_txn_time
    FROM transactions
),
dormant_points AS (
    SELECT
        user_id,
        txn_time AS active_start_time
    FROM transaction_gaps
    WHERE previous_txn_time IS NOT NULL
      AND DATEDIFF(txn_time, previous_txn_time) >= 90
),
post_gap_activity AS (
    SELECT
        d.user_id,
        d.active_start_time,
        COUNT(t.txn_id) AS post_gap_transactions
    FROM dormant_points d
    JOIN transactions t
        ON t.user_id = d.user_id
       AND t.txn_time >= d.active_start_time
    GROUP BY
        d.user_id,
        d.active_start_time
)
SELECT
    user_id,
    active_start_time,
    post_gap_transactions
FROM post_gap_activity
WHERE post_gap_transactions >= 15
ORDER BY post_gap_transactions DESC;

-- Findings:
-- Suspect count: 26 users
-- Examples: See the query result for users with the highest
-- post-dormancy transaction activity.

-- =====================================================================
-- P11: Velocity Spike
-- Detect users whose peak monthly transaction count is at least
-- 3 times their average monthly transaction count, with a peak
-- of at least 20 transactions.
-- =====================================================================

WITH monthly_transactions AS (
    SELECT
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m') AS transaction_month,
        COUNT(*) AS monthly_transaction_count
    FROM transactions
    GROUP BY
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m')
),
user_monthly_stats AS (
    SELECT
        user_id,
        AVG(monthly_transaction_count) AS average_monthly_transactions,
        MAX(monthly_transaction_count) AS peak_monthly_transactions
    FROM monthly_transactions
    GROUP BY user_id
)
SELECT
    user_id,
    ROUND(average_monthly_transactions, 2) AS average_monthly_transactions,
    peak_monthly_transactions,
    ROUND(
        peak_monthly_transactions / average_monthly_transactions,
        2
    ) AS peak_to_average_ratio
FROM user_monthly_stats
WHERE peak_monthly_transactions >= 20
  AND peak_monthly_transactions / average_monthly_transactions >= 3
ORDER BY peak_to_average_ratio DESC;

-- Findings:
-- Suspect count: 45 users
-- Examples: User 14517 had a peak of 41 transactions against
-- an average of 8.00 transactions per month (5.13x).
-- User 14504 had a peak of 45 transactions against
-- an average of 8.83 transactions per month (5.09x).

-- =====================================================================
-- P12: Rapid Geographic Shift
-- Detect users who make consecutive transactions in different cities
-- within 60 minutes, which may indicate impossible travel.
-- =====================================================================

WITH transaction_locations AS (
    SELECT
        user_id,
        txn_time,
        city,
        LAG(city) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_city,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_txn_time
    FROM transactions
),
suspicious_pairs AS (
    SELECT
        user_id,
        previous_city,
        city AS current_city,
        previous_txn_time,
        txn_time AS current_txn_time,
        TIMESTAMPDIFF(
            MINUTE,
            previous_txn_time,
            txn_time
        ) AS minutes_between_transactions,
        ROW_NUMBER() OVER (
            PARTITION BY user_id
            ORDER BY
                TIMESTAMPDIFF(
                    MINUTE,
                    previous_txn_time,
                    txn_time
                )
        ) AS pair_rank
    FROM transaction_locations
    WHERE previous_city IS NOT NULL
      AND city IS NOT NULL
      AND city <> previous_city
      AND TIMESTAMPDIFF(
            MINUTE,
            previous_txn_time,
            txn_time
          ) <= 60
)
SELECT
    user_id,
    previous_city,
    current_city,
    previous_txn_time,
    current_txn_time,
    minutes_between_transactions
FROM suspicious_pairs
WHERE pair_rank = 1
ORDER BY minutes_between_transactions ASC;

-- Findings:
-- Suspect count: 15 users
-- Examples:
-- User 14750: Visakhapatnam to Delhi in 1 minute.
-- User 14745: Surat to Thiruvananthapuram in 9 minutes.