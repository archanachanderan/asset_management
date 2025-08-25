
# Database Schema Overview

## `approval`
| Column      | Type                   | Constraints                                                         |
|-------------|------------------------|----------------------------------------------------------------------|
| id          | integer                | PRIMARY KEY                                                         |
| request_id  | integer                | FK → `requests(id)`                                                 |
| approved_by | integer                | FK → `user_details(id)`                                             |
| status      | varchar(20)            | NOT NULL, CHECK IN ('Approved', 'Rejected')                         |
| remarks     | text                   |                                                                      |
| decided_at  | timestamp              | DEFAULT CURRENT_TIMESTAMP                                           |

## `asset`
| Column        | Type             | Constraints                                                      |
|---------------|------------------|-------------------------------------------------------------------|
| id            | integer          | PRIMARY KEY                                                      |
| asset_name    | varchar(100)     | NOT NULL                                                         |
| description   | text             |                                                                   |
| category_id   | integer          | FK → `category(id)`                                              |
| status        | varchar(50)      | DEFAULT 'Active'                                                 |
| purchase_date | date             |                                                                   |
| purchase_cost | numeric(12,2)    |                                                                   |
| is_active     | boolean          | DEFAULT true                                                     |
| created_at    | timestamp        | DEFAULT CURRENT_TIMESTAMP                                        |
| updated_at    | timestamp        | DEFAULT CURRENT_TIMESTAMP                                        |
| tag           | varchar(100)     | NOT NULL                                                         |

## `assignments`
| Column          | Type     | Constraints                          |
|-----------------|----------|--------------------------------------|
| id              | integer  | PRIMARY KEY                          |
| asset_id        | integer  | NOT NULL, FK → `asset(id)`           |
| user_id         | integer  |                                      |
| assigned_date   | date     | NOT NULL                             |
| unassigned_date | date     |                                      |
| remarks         | text     |                                      |
| is_active       | boolean  | DEFAULT true                         |

## `category`
| Column     | Type             | Constraints                            |
|------------|------------------|----------------------------------------|
| id         | integer          | PRIMARY KEY                            |
| name       | varchar(100)     | NOT NULL                               |
| parent_id  | integer          | FK → `category(id)`                    |
| is_active  | boolean          | DEFAULT true                           |

## `files`
| Column       | Type             | Constraints                                                  |
|--------------|------------------|---------------------------------------------------------------|
| id           | integer          | PRIMARY KEY                                                  |
| asset_id     | integer          | FK → `asset(id)` ON DELETE CASCADE                           |
| part_id      | integer          | FK → `part(id)` ON DELETE CASCADE                            |
| file_name    | varchar(255)     | NOT NULL                                                     |
| file_type    | varchar(50)      |                                                               |
| file_path    | text             | NOT NULL                                                     |
| uploaded_by  | integer          | FK → `user_details(id)`                                      |
| uploaded_at  | timestamp        | DEFAULT CURRENT_TIMESTAMP                                    |
| is_active    | boolean          | DEFAULT true                                                 |

## `insurances`
| Column        | Type             | Constraints                              |
|---------------|------------------|------------------------------------------|
| id            | integer          | PRIMARY KEY                              |
| asset_id      | integer          | FK → `asset(id)` ON DELETE CASCADE       |
| policy_number | varchar(100)     | NOT NULL                                 |
| provider      | varchar(100)     | NOT NULL                                 |
| insured_value | numeric(12,2)    |                                          |
| start_date    | date             | NOT NULL                                 |
| end_date      | date             | NOT NULL                                 |
| comments      | text             |                                          |
| is_active     | boolean          | DEFAULT true                             |

## `warranty`
| Column             | Type             | Constraints                                       |
|--------------------|------------------|---------------------------------------------------|
| id                 | integer          | PRIMARY KEY                                       |
| asset_id           | integer          | NOT NULL, FK → `asset(id)` ON DELETE CASCADE     |
| warranty_provider  | varchar(100)     |                                                   |
| start_date         | date             | NOT NULL                                          |
| end_date           | date             | NOT NULL                                          |
| terms              | text             |                                                   |
| is_active          | boolean          | DEFAULT true                                      |

## `maintenance`
| Column              | Type             | Constraints                                             |
|---------------------|------------------|---------------------------------------------------------|
| id                  | integer          | PRIMARY KEY                                             |
| asset_id            | integer          | NOT NULL, FK → `asset(id)`                              |
| task_done           | text             | NOT NULL                                                |
| maintenance_date    | date             | NOT NULL                                                |
| cost                | numeric(10,2)    |                                                         |
| service_by          | text             |                                                         |
| external_provider_id| integer          | FK → `vendors(id)`                                      |
| parts_used          | text             |                                                         |
| comments            | text             |                                                         |
| is_active           | boolean          | DEFAULT true                                            |

## `logs`
| Column       | Type              | Constraints                              |
|--------------|-------------------|------------------------------------------|
| id           | integer           | PRIMARY KEY                              |
| table_name   | varchar(100)      | NOT NULL                                 |
| record_id    | integer           | NOT NULL                                 |
| action       | varchar(50)       | NOT NULL                                 |
| description  | text              |                                          |
| performed_by | integer           | FK → `user_details(id)`                  |
| performed_at | timestamp         | DEFAULT CURRENT_TIMESTAMP                |
| is_active    | boolean           | DEFAULT true                             |

## `requests`
| Column        | Type             | Constraints                                                        |
|---------------|------------------|---------------------------------------------------------------------|
| id            | integer          | PRIMARY KEY                                                        |
| request_type  | varchar(50)      | NOT NULL, CHECK IN ('add', 'edit', 'repair', 'maintenance')        |
| requested_by  | integer          | NOT NULL, FK → `user_details(id)`                                  |
| asset_id      | integer          | FK → `asset(id)`                                                   |
| request_date  | timestamp        | DEFAULT CURRENT_TIMESTAMP                                          |
| status        | varchar(20)      | NOT NULL, DEFAULT 'Pending', CHECK IN ('Pending', 'Approved', 'Rejected') |
| remarks       | text             |                                                                     |
| is_active     | boolean          | DEFAULT true                                                       |

## `vendors`
| Column     | Type             | Constraints                             |
|------------|------------------|-----------------------------------------|
| id         | integer          | PRIMARY KEY                             |
| name       | varchar(100)     | NOT NULL                                |
| email      | varchar(100)     |                                         |
| phone      | varchar(20)      |                                         |
| address    | text             |                                         |
| is_active  | boolean          | DEFAULT true                            |
| asset_id   | integer          | FK → `asset(id)`                        |

## `role`
| Column | Type             | Constraints           |
|--------|------------------|------------------------|
| id     | integer          | PRIMARY KEY            |
| name   | varchar(50)      | NOT NULL, UNIQUE       |

## `user_details`
| Column               | Type              | Constraints                                |
|----------------------|-------------------|--------------------------------------------|
| id                   | integer           | PRIMARY KEY                                |
| name                 | varchar(100)      | NOT NULL                                   |
| email                | varchar(100)      | NOT NULL, UNIQUE                           |
| password_hash        | text              | NOT NULL                                   |
| role_id              | integer           | FK → `role(id)`                            |
| is_active            | boolean           | DEFAULT true                               |
| created_at           | timestamp         | DEFAULT CURRENT_TIMESTAMP                  |
| last_login           | timestamp         |                                            |
| force_password_reset | boolean           | DEFAULT false                              |

## `part`
| Column      | Type             | Constraints         |
|-------------|------------------|----------------------|
| id          | integer          | PRIMARY KEY         |
| name        | varchar(100)     | NOT NULL            |
| description | text             |                     |
| is_active   | boolean          | DEFAULT true        |
