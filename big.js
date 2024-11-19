const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');  // 해시화 모듈
const crypto = require('crypto');  // 암호화 모듈
const jwt = require('jsonwebtoken');  // JWT 모듈
const multer = require('multer');  // 파일 업로드 모듈
const path = require('path');  // 경로 모듈
const fs = require('fs');

const app = express();
const secretKey = 'cmslauncher';

app.use(cors());
app.use(bodyParser.json());

// 데이터베이스 연결 설정
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'user_db',
    charset: 'utf8mb4'
});

//sj
const connection2 = mysql.createConnection({
    host: 'cmsimulator.co.kr',
    user: 'tdmaxkim',
    password: 'seo25560302^',
    database: 'tdmaxkim',
    charset: 'utf8mb4'
});

// 파일 
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

// 파일 전송 API
app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'uploads', filename);

    res.sendFile(filePath, (err) => {
        if (err) {
            console.error('파일 전송 중 에러 발생:', err);
            res.status(500).json({ success: false, error: '파일 전송 중 에러 발생' });
        }
    });
});

const session = require('express-session');

app.use(session({
    secret: 'bsiegcpriicttkueryes',  // 세션 암호화에 사용될 키
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }   // HTTPS가 아닌 경우 false로 설정
}));

// AES-256 암호화를 위한 키 설정 (32바이트)
const key = Buffer.from('0123456789abcdef0123456789abcdef'); // 정확히 32바이트

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// 암호화 함수
function encrypt(text) {
    const iv = crypto.randomBytes(16); // 16바이트 IV 생성
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), encryptedData: encrypted };
}

// 복호화 함수
function decrypt(encrypted) {
    const iv = Buffer.from(encrypted.iv, 'hex');
    const encryptedText = Buffer.from(encrypted.encryptedData, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// 미들웨어를 추가하여 모든 요청을 UTF-8로 인코딩
app.use((req, res, next) => {
    if (req.query.title) {
        req.query.title = decodeURIComponent(req.query.title);
    }
    next();
});

// 데이터베이스 연결 확인
connection.connect((err) => {
    if (err) {
        console.error('데이터베이스 연결 실패: ' + err.stack);
        return;
    }
    console.log('데이터베이스 연결됨: ' + connection.threadId);
});


// 로그인 API
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    // 암호화된 username을 데이터베이스에서 검색
    const sql = 'SELECT * FROM users WHERE username = ?';

    connection.query(sql, [username], (error, results) => {
        if (error) {
            console.error('SQL Error:', error);
            return res.status(500).json({success : false, error : '서버 에러'});
        }
        if (results.length === 0) {
            return res.status(404).json({success : false, error : '아이디 또는 비밀번호가 틀립니다.'});
        }

        const user = results[0];

        // 비밀번호 비교 (bcrypt 해시된 비밀번호)
        bcrypt.compare(password, user.password, (err, match) => {
            if (err) {
                console.error('bcrypt Error:', err);
                return res.status(500).json('비밀번호 비교 중 에러 발생');
            }
            if (match) {
                const token = jwt.sign(
                    {id : user.id, username: user.username },
                    secretKey,
                    { expiresIn: '100s'}
                );
                return res.json({ success: true, message: '로그인 성공!', token});
            } else {
                return res.status(401).json({success : false, error : '아이디 또는 비밀번호가 틀립니다.'});
            }
        });
    });
});

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(403).json({ success: false, error: '토큰이 필요합니다.' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, error: '유효하지 않은 토큰입니다.' });
        }
        req.user = decoded;
        next();
    });
};

// JWT 검증 API
app.post('/api/verify-token', verifyToken, (req, res) => {
    // 토큰이 유효한 경우, 접근 허용 메시지 반환
    res.json({ success: true, message: '토큰이 유효합니다!', user: req.user });
});


// 회원가입 API
app.get('/api/addData', (req, res) => {
    const { username, password, password2, num } = req.query;

    if (!username) {
        return res.status(400).json('이름을 입력해주세요.');
    }

    if (!password) {
        return res.status(400).json('비밀번호를 입력해주세요.');
    }

    if (password !== password2) {
        return res.status(400).json('비밀번호가 같지 않습니다.');
    }

    if (!num) {
        return res.status(400).json('번호를 입력해주세요.');
    }

    // num 형식 검사 (000-0000-0000)
    const numPattern = /^\d{3}-\d{4}-\d{4}$/;
    if (!numPattern.test(num)) {
        return res.status(400).json('번호는 000-0000-0000 형식이어야 합니다.');
    }

    // 이름과 번호 암호화
    const encryptedUsername = encrypt(username);
    const encryptedNum = encrypt(num);

    // 사용자 이름과 번호 중복 검사
    const checkSql = 'SELECT * FROM member WHERE username = ? OR num = ?';
    connection.query(checkSql, [encryptedUsername, encryptedNum], (error, results) => {
        if (error) {
            console.error('SQL Error:', error);
            return res.status(500).json('서버 에러');
        }
        if (results.length > 0) {
            const existingUser = results.find(user => user.username === encryptedUsername);
            const existingNum = results.find(user => user.num === encryptedNum);
            if (existingUser) {
                return res.status(400).json('이미 존재하는 이름입니다.');
            }
            if (existingNum) {
                return res.status(400).json('이미 존재하는 번호입니다.');
            }
        }

        // 비밀번호 해시화
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.error('bcrypt Error:', err);
                return res.status(500).json('비밀번호 해시화 실패');
            }

            // 암호화된 username, hashed password, 암호화된 num 저장
            const sqlInsert = 'INSERT INTO member (username, password, num) VALUES (?, ?, ?)';
            connection.query(sqlInsert, [encryptedUsername, hash, encryptedNum], (error, results) => {
                if (error) {
                    console.error('SQL Insert Error:', error);
                    return res.status(500).json('회원가입 실패');
                }
                return res.status(201).json('회원가입 완료!');
            });
        });
    });
});


// 공지사항 제목 API
app.get('/api/gongt', (req, res) => {
    const sqlSelect = 'SELECT title FROM gong';  // 모든 title을 선택
    // const sqlSelect = 'SELECT title FROM gong WHERE id <= 4';  // id가 4 이하인 title 선택

    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 모든 title을 배열로 반환
        const titles = results.map(row => row.title);
        res.json({ titles: titles });  // JSON 배열로 반환
    });
});


// 공지사항 번호 API
app.get('/api/gongid', (req, res) => {
    const sqlSelect = 'SELECT id FROM gong';  
    // const sqlSelect = 'SELECT id FROM gong WHERE id <= 4';  // id가 4 이하인 id 선택
    
    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 모든 id를 문자열로 변환하여 배열로 반환
        const ids = results.map(row => String(row.id));
        res.json({ ids: ids });  // JSON 배열로 반환
    });
});


// 공지사항 날짜 API
app.get('/api/gongd', (req, res) => {
    const sqlSelect = 'SELECT DATE_FORMAT(date, "%Y-%m-%d") AS date FROM gong';  // 연도-월-일 형식으로 날짜 선택

    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 모든 날짜를 배열로 반환
        const dates = results.map(row => row.date);
        res.json({ dates: dates });  // JSON 배열로 반환
    });
});


// 공지사항 내용 API
app.get('/api/gongc', (req, res) => {
    const { title } = req.query; // 요청에서 title을 받습니다.
    const sqlSelect = 'SELECT content FROM gong WHERE title = ?'; // 특정 공지의 내용을 제목으로 가져옴

    connection.query(sqlSelect, [title], (error, results) => {
        if (error) {
            console.error('Database Error:', error);
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            console.log('No Data Found');
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 선택한 공지의 내용을 반환
        const data = results[0].content;
        res.json({ content: data }); // JSON으로 반환
    });
});


// 공지사항 내용(이미지) API
app.get('/api/gongi', (req, res) => {
    const { title } = req.query; 
    const sqlSelect = 'SELECT image FROM gong WHERE title = ?';

    connection.query(sqlSelect, [title], (error, results) => {
        if (error) {
            console.error('Database Error:', error);
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        const imageBuffer = results[0].image;
        if (!imageBuffer) {
            return res.status(404).json({ message: '이미지 데이터가 없습니다.' });
        }

        const base64Image = imageBuffer.toString('base64');
        res.json({ image: base64Image });
    });
});




//여기부터 시안 내용




// 장비보기 제목 API
app.get('/api/jangt', (req, res) => {
    const sqlSelect = 'SELECT title FROM jang';  

    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 모든 title을 배열로 반환
        const titles = results.map(row => row.title);
        res.json({ titles: titles });  // JSON 배열로 반환
    });
});


// 장비보기 번호 API
app.get('/api/jangid', (req, res) => {
    const sqlSelect = 'SELECT id FROM jang';  
    
    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 모든 id를 문자열로 변환하여 배열로 반환
        const ids = results.map(row => String(row.id));
        res.json({ ids: ids });  // JSON 배열로 반환
    });
});


// 장비보기 내용 API
app.get('/api/jangc', (req, res) => {
    const { title } = req.query; // 요청에서 title을 받습니다.
    const sqlSelect = 'SELECT content FROM jang WHERE title = ?'; // 특정 공지의 내용을 제목으로 가져옴

    connection.query(sqlSelect, [title], (error, results) => {
        if (error) {
            console.error('Database Error:', error);
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            console.log('No Data Found');
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 선택한 공지의 내용을 반환
        const data = results[0].content;
        res.json({ content: data }); // JSON으로 반환
    });
});


// 장비보기 내용(이미지) API
app.get('/api/jangi', (req, res) => {
    const { title } = req.query; 
    const sqlSelect = 'SELECT image FROM jang WHERE title = ?';

    connection.query(sqlSelect, [title], (error, results) => {
        if (error) {
            console.error('Database Error:', error);
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        const imageBuffer = results[0].image;
        if (!imageBuffer) {
            return res.status(404).json({ message: '이미지 데이터가 없습니다.' });
        }

        const base64Image = imageBuffer.toString('base64');
        res.json({ image: base64Image });
    });
});


// 업데이트 제목 API
app.get('/api/upt', (req, res) => {
    const sqlSelect = 'SELECT title FROM up';  

    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 모든 title을 배열로 반환
        const titles = results.map(row => row.title);
        res.json({ titles: titles });  // JSON 배열로 반환
    });
});


// 업데이트 번호 API
app.get('/api/upid', (req, res) => {
    const sqlSelect = 'SELECT id FROM up';  
    
    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 모든 id를 문자열로 변환하여 배열로 반환
        const ids = results.map(row => String(row.id));
        res.json({ ids: ids });  // JSON 배열로 반환
    });
});


// 업데이트 내용 API
app.get('/api/upc', (req, res) => {
    const { title } = req.query; // 요청에서 title을 받습니다.
    const sqlSelect = 'SELECT content FROM up WHERE title = ?'; // 특정 공지의 내용을 제목으로 가져옴

    connection.query(sqlSelect, [title], (error, results) => {
        if (error) {
            console.error('Database Error:', error);
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            console.log('No Data Found');
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 선택한 공지의 내용을 반환
        const data = results[0].content;
        res.json({ content: data }); // JSON으로 반환
    });
});


// 업데이트 내용(이미지) API
app.get('/api/upi', (req, res) => {
    const { title } = req.query; 
    const sqlSelect = 'SELECT image FROM up WHERE title = ?';

    connection.query(sqlSelect, [title], (error, results) => {
        if (error) {
            console.error('Database Error:', error);
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        const imageBuffer = results[0].image;
        if (!imageBuffer) {
            return res.status(404).json({ message: '이미지 데이터가 없습니다.' });
        }

        const base64Image = imageBuffer.toString('base64');
        res.json({ image: base64Image });
    });
});


// 광고 이미지 API 
app.get('/api/ad', (req, res) => {
    const { id } = req.query;  // 쿼리로 이미지 ID를 받음

    // 현재 ID에 해당하는 이미지를 가져오는 SQL 쿼리
    const sqlSelect = 'SELECT image FROM image WHERE id = ?';

    // 최대 ID 값을 가져오는 SQL 쿼리
    const sqlMaxId = 'SELECT MAX(id) AS max_id FROM image';

    connection.query(sqlSelect, [id], (error, results) => {
        if (error) {
            console.error('Database Error:', error);
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '이미지가 없습니다.' });
        }

        const imageBuffer = results[0].image;
        if (!imageBuffer) {
            return res.status(404).json({ message: '이미지 데이터가 없습니다.' });
        }

        // BLOB 데이터를 Base64로 변환
        const base64Image = imageBuffer.toString('base64');

        // 최대 ID를 가져오기 위해 또 다른 쿼리 실행
        connection.query(sqlMaxId, (error, maxIdResults) => {
            if (error) {
                console.error('Database Error:', error);
                return res.status(500).json({ error: '최대 ID 가져오는 중 오류 발생' });
            }

            const maxId = maxIdResults[0].max_id;

            // Base64 이미지와 최대 ID를 JSON으로 전송
            res.json({ image: base64Image, max_id: maxId });
        });
    });
});


// 이미지 스와이프 API (GET 방식)
app.get('/api/swipeimage', (req, res) => {
    const { id } = req.query;  // 쿼리로 이미지 ID를 받음

    // 현재 ID에 해당하는 이미지를 가져오는 SQL 쿼리
    const sqlSelect = 'SELECT image FROM swipe_image WHERE id = ?';

    // 최대 ID 값을 가져오는 SQL 쿼리
    const sqlMaxId = 'SELECT MAX(id) AS max_id FROM swipe_image';

    connection.query(sqlSelect, [id], (error, results) => {
        if (error) {
            console.error('Database Error:', error);
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '이미지가 없습니다.' });
        }

        const imageBuffer = results[0].image;
        if (!imageBuffer) {
            return res.status(404).json({ message: '이미지 데이터가 없습니다.' });
        }

        // BLOB 데이터를 Base64로 변환
        const base64Image = imageBuffer.toString('base64');

        // 최대 ID를 가져오기 위해 또 다른 쿼리 실행
        connection.query(sqlMaxId, (error, maxIdResults) => {
            if (error) {
                console.error('Database Error:', error);
                return res.status(500).json({ error: '최대 ID 가져오는 중 오류 발생' });
            }

            const maxId = maxIdResults[0].max_id;

            // Base64 이미지와 최대 ID를 JSON으로 전송
            res.json({ image: base64Image, max_id: maxId });
        });
    });
});


// 로그아웃 API 
app.get('/api/logout', (req, res) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json('로그아웃 중 오류가 발생했습니다.');
            }
            // 세션 쿠키 삭제
            res.clearCookie('connect.sid');
            return res.status(200).json('로그아웃 성공');
        });
    } else {
        return res.status(400).json('로그인 상태가 아닙니다.');
    }
});


// admin 이름 (복호화된 상태로 반환)
app.get('/api/aname', (req, res) => {
    const sqlSelect = 'SELECT username FROM member'; 

    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 각 username을 복호화하여 반환
        const usernames = results.map(row => decrypt(row.username));
        res.json({ usernames: usernames }); 
    });
});


// admin 비번
app.get('/api/apw', (req, res) => {
    const sqlSelect = 'SELECT password FROM member'; 

    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        const passwords = results.map(row => row.password);
        res.json({ passwords: passwords }); 
    });
});


// admin 전화번호
app.get('/api/anum', (req, res) => {
    const sqlSelect = 'SELECT num FROM member'; 

    connection.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        const nums = results.map(row => decrypt(row.num));
        res.json({ nums: nums }); 
    });
});


//sj

// 공지사항 제목 API
app.get('/api/ggongt', (req, res) => {
    const sqlSelect = 'SELECT wr_subject FROM g5_write_notice ORDER BY wr_num ASC LIMIT 4';  // wr_num을 기준으로 오름차순 정렬 후 상위 4개 선택
    
    connection2.query(sqlSelect, (error, results) => {
        if (error) {
            console.error('Database Error:', error);  // 에러 메시지 출력
            return res.status(500).json({ error: '서버 내부 오류가 발생했습니다.' });
        }
    
        if (results.length === 0) {
            console.log('No Data Found');
            return res.status(404).json({ message: '공지사항을 찾을 수 없습니다.' });
        }
    
        // Buffer 데이터를 UTF-8 문자열로 변환
        const titles = results.map(row => row.wr_subject.toString('utf8'));

        // 응답에 "공지사항"이라는 추가 메시지를 포함하여 전송
        res.json({ titles: titles });
    });    
});



// 공지사항 번호 API
app.get('/api/ggongid', (req, res) => {
    // wr_num을 절대값으로 변환하여 오름차순으로 정렬
    const sqlSelect = 'SELECT DISTINCT ABS(wr_num) AS wr_num FROM g5_write_notice ORDER BY ABS(wr_num) DESC LIMIT 4';
    connection2.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // 모든 wr_num 값을 문자열로 변환하여 배열로 반환
        const ids = results.map(row => String(row.wr_num));
        res.json({ ids: ids });  // JSON 배열로 반환
    });
});


// 공지사항 날짜 API
app.get('/api/ggongd', (req, res) => {
    // wr_datetime에서 년-월-일 형식으로 변환하여 오름차순 정렬
    const sqlSelect = 'SELECT DATE_FORMAT(wr_datetime, "%y-%m-%d") AS formatted_date FROM g5_write_notice ORDER BY ABS(wr_num) DESC LIMIT 4';
    
    connection2.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        // 결과가 없을 경우
        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        // formatted_date 값을 문자열로 변환하여 배열로 반환
        const dates = results.map(row => row.formatted_date.toString());
        res.json({ dates: dates });  // JSON 배열로 반환
    });
});



// 전시일정 제목 API
app.get('/api/junt', (req, res) => {
    const sqlSelect = 'SELECT wr_subject FROM g5_write_exhibition ORDER BY wr_num ASC LIMIT 4';  
    connection2.query(sqlSelect, (error, results) => {
        if (error) {
            console.error('Database Error:', error);  
            return res.status(500).json({ error: '서버 내부 오류가 발생했습니다.' });
        }
    
        if (results.length === 0) {
            console.log('No Data Found');
            return res.status(404).json({ message: '공지사항을 찾을 수 없습니다.' });
        }
    
        const titles = results.map(row => row.wr_subject.toString('utf8'));
        res.json({ titles: titles });
    });    
});


// 전시일정 번호 API
app.get('/api/junid', (req, res) => {
    const sqlSelect = 'SELECT DISTINCT ABS(wr_num) AS wr_num FROM g5_write_exhibition ORDER BY ABS(wr_num) DESC LIMIT 4';
    connection2.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        const ids = results.map(row => String(row.wr_num));
        res.json({ ids: ids });  
    });
});


// 전시일정 날짜 API
app.get('/api/jund', (req, res) => {
    const sqlSelect = 'SELECT DATE_FORMAT(wr_datetime, "%y-%m-%d") AS formatted_date FROM g5_write_exhibition ORDER BY ABS(wr_num) DESC LIMIT 4';
    
    connection2.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        const dates = results.map(row => row.formatted_date.toString());
        res.json({ dates: dates });  
    });
});


// 출시정보 제목 API
app.get('/api/chult', (req, res) => {
    const sqlSelect = 'SELECT wr_subject FROM g5_write_launch ORDER BY wr_num ASC LIMIT 4'; 
    connection2.query(sqlSelect, (error, results) => {
        if (error) {
            console.error('Database Error:', error);  
            return res.status(500).json({ error: '서버 내부 오류가 발생했습니다.' });
        }
    
        if (results.length === 0) {
            console.log('No Data Found');
            return res.status(404).json({ message: '공지사항을 찾을 수 없습니다.' });
        }
    
        const titles = results.map(row => row.wr_subject.toString('utf8'));
        res.json({ titles: titles });
    });    
});


// 출시정보 번호 API
app.get('/api/chulid', (req, res) => {
    const sqlSelect = 'SELECT DISTINCT ABS(wr_num) AS wr_num FROM g5_write_launch ORDER BY ABS(wr_num) DESC LIMIT 4';

    connection2.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        const ids = results.map(row => String(row.wr_num));
        res.json({ ids: ids }); 
    });
});


// 출시정보 날짜 API
app.get('/api/chuld', (req, res) => {
    const sqlSelect = 'SELECT DATE_FORMAT(wr_datetime, "%y-%m-%d") AS formatted_date FROM g5_write_launch  ORDER BY ABS(wr_num) DESC LIMIT 4';
    
    connection2.query(sqlSelect, (error, results) => {
        if (error) {
            return res.status(500).json({ error: '데이터베이스 오류' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '데이터가 없습니다.' });
        }

        const dates = results.map(row => row.formatted_date.toString());
        res.json({ dates: dates }); 
    });
});


// 미들웨어 설정
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// 여러 테이블에서 데이터 가져와 HTML 파일 생성하는 함수
function generateHTMLFiles() {
    // 테이블 이름 목록
    const tables = ['g5_write_notice', 'g5_write_launch', 'g5_write_exhibition'];
    
    tables.forEach((table) => {
        const query = `SELECT wr_subject, wr_content FROM ${table}`;
        
        connection2.query(query, (error, results) => {
            if (error) {
                console.error(`데이터베이스 조회 오류 (${table}):`, error);
                return;
            }

            // 결과가 있을 때마다 파일을 생성
            results.forEach(row => {
                let wrSubject = row.wr_subject;

                // wr_subject 값이 문자열인지 확인하고 문자열이 아니면 변환
                if (typeof wrSubject !== 'string') {
                    wrSubject = String(wrSubject);  // 문자열로 변환
                }

                // 글자 수 제한 (50자까지)
                const trimmedSubject = wrSubject.length > 50 ? wrSubject.substring(0, 50) : wrSubject;

                // 특수문자 처리
                const sanitizedSubject = trimmedSubject.replace(/[^a-zA-Z0-9가-힣_-]/g, '_');

                // HTML 템플릿 생성
                const htmlTemplate = `
                <!DOCTYPE html>
                <html lang="ko">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>${sanitizedSubject}</title>
                </head>
                <body>
                    ${row.wr_content}
                </body>
                </html>
                `;

                // 파일로 저장 (제목만을 파일명으로 사용)
                const filePath = path.join(__dirname, 'public', `${sanitizedSubject}.html`);
                fs.writeFile(filePath, htmlTemplate, (err) => {
                    if (err) {
                        console.error('파일 저장에 실패했습니다:', err);
                    }
                });
            });
        });
    });
}

// 서버 시작 시 또는 주기적으로 실행될 수 있도록 함수 호출
generateHTMLFiles();

// 동적으로 생성된 HTML 파일을 제공하는 라우트
app.get('/:filename', (req, res) => {
    // 새로 고침할 때마다 데이터베이스에서 다시 HTML 생성
    generateHTMLFiles();
    
    // URL에서 인코딩된 파일 이름을 디코딩
    const fileName = decodeURIComponent(req.params.filename);
    const filePath = path.join(__dirname, 'public', `${fileName}.html`);

    // 파일이 존재하는지 확인
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            return res.status(404).send('404 - 해당 메모를 찾을 수 없습니다.');
        }
        res.sendFile(filePath);
    });
});


// 공지사항 이전 글
app.get('/api/ggongmnum', (req, res) => {
    const { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    // title의 글자 수 확인
    const titleLength = title.length;
    const isTitleLong = titleLength >= 50;

    // title의 길이에 따라 쿼리문을 다르게 설정
    const query = isTitleLong
        ? `
            SELECT wr_num 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_notice WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_notice WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '해당 제목에 대한 wr_num을 찾을 수 없습니다.' });
        }

        // wr_num에 +1 한 값을 계산
        const incrementedWrNum = results[0].wr_num + 1;

        // +1 한 wr_num에 해당하는 wr_subject 찾기
        const subjectQuery = `
            SELECT wr_subject 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(subjectQuery, [incrementedWrNum], (subjectError, subjectResults) => {
            if (subjectError) {
                console.error('쿼리 오류:', subjectError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (subjectResults.length === 0) {
                return res.status(404).send('NO_DATA');
            }

            // wr_subject 반환
            res.send(subjectResults[0].wr_subject);
        });
    });
});


// 공지사항 다음글
app.get('/api/ggongpnum', (req, res) => {
    let { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    // title의 길이를 확인하여 50자 이상인지 확인
    const titleLength = title.length;
    const isTitleLong = titleLength >= 50;

    // `title`의 길이에 따라 쿼리문을 다르게 설정
    const query = isTitleLong
        ? `
            SELECT wr_num 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_notice WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_notice WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '해당 제목에 대한 wr_num을 찾을 수 없습니다.' });
        }

        // wr_num에 -1 한 값을 계산
        const incrementedWrNum = results[0].wr_num - 1;

        // -1 한 wr_num에 해당하는 wr_subject 찾기
        const subjectQuery = `
            SELECT wr_subject 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(subjectQuery, [incrementedWrNum], (subjectError, subjectResults) => {
            if (subjectError) {
                console.error('쿼리 오류:', subjectError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (subjectResults.length === 0) {
                return res.status(404).send('NO_DATA');
            }

            // wr_subject 반환
            res.send(subjectResults[0].wr_subject);
        });
    });
});


// 공지사항 이전 날짜
app.get('/api/ggongmdate', (req, res) => {
    const { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    // title의 길이에 따라 쿼리문을 다르게 설정
    const query = title.length >= 50
        ? `
            SELECT wr_num 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_notice WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_notice WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).send('해당 제목에 대한 wr_num을 찾을 수 없습니다.');
        }

        // wr_num에 +1 한 값을 계산
        const incrementedWrNum = results[0].wr_num + 1;

        // +1 한 wr_num에 해당하는 wr_datetime 찾기
        const dateQuery = `
            SELECT DATE_FORMAT(wr_datetime, "%y-%m-%d") AS formatted_date 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(dateQuery, [incrementedWrNum], (dateError, dateResults) => {
            if (dateError) {
                console.error('쿼리 오류:', dateError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (dateResults.length === 0) {
                return res.status(404).send(' ');
            }

            // 날짜 문자열만 반환
            res.send(dateResults[0].formatted_date);
        });
    });
});


// 공지사항 다음 날짜
app.get('/api/ggongndate', (req, res) => {
    const { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    // title의 길이에 따라 쿼리문을 다르게 설정
    const query = title.length >= 50
        ? `
            SELECT wr_num 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_notice WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_notice WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).send('해당 제목에 대한 wr_num을 찾을 수 없습니다.');
        }

        // wr_num에 +1 한 값을 계산
        const incrementedWrNum = results[0].wr_num - 1;

        // +1 한 wr_num에 해당하는 wr_datetime 찾기
        const dateQuery = `
            SELECT DATE_FORMAT(wr_datetime, "%y-%m-%d") AS formatted_date 
            FROM g5_write_notice 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(dateQuery, [incrementedWrNum], (dateError, dateResults) => {
            if (dateError) {
                console.error('쿼리 오류:', dateError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (dateResults.length === 0) {
                return res.status(404).send(' ');
            }

            // 날짜 문자열만 반환
            res.send(dateResults[0].formatted_date);
        });
    });
});


// 출시정보 이전 글
app.get('/api/chulmnum', (req, res) => {
    const { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    const titleLength = title.length;
    const isTitleLong = titleLength >= 50;

    const query = isTitleLong
        ? `
            SELECT wr_num 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_launch WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_launch WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '해당 제목에 대한 wr_num을 찾을 수 없습니다.' });
        }

        const incrementedWrNum = results[0].wr_num + 1;

        const subjectQuery = `
            SELECT wr_subject 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(subjectQuery, [incrementedWrNum], (subjectError, subjectResults) => {
            if (subjectError) {
                console.error('쿼리 오류:', subjectError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (subjectResults.length === 0) {
                return res.status(404).send(' ');
            }

            res.send(subjectResults[0].wr_subject);
        });
    });
});


// 출시정보 다음글
app.get('/api/chulpnum', (req, res) => {
    let { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    const titleLength = title.length;
    const isTitleLong = titleLength >= 50;

    const query = isTitleLong
        ? `
            SELECT wr_num 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_launch WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_launch
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_launch WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '해당 제목에 대한 wr_num을 찾을 수 없습니다.' });
        }

        const incrementedWrNum = results[0].wr_num - 1;

        const subjectQuery = `
            SELECT wr_subject 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(subjectQuery, [incrementedWrNum], (subjectError, subjectResults) => {
            if (subjectError) {
                console.error('쿼리 오류:', subjectError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (subjectResults.length === 0) {
                return res.status(404).send(' ');
            }

            res.send(subjectResults[0].wr_subject);
        });
    });
});


// 출시정보 이전 날짜
app.get('/api/chulmdate', (req, res) => {
    const { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    const query = title.length >= 50
        ? `
            SELECT wr_num 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_launch WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_launch WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).send('해당 제목에 대한 wr_num을 찾을 수 없습니다.');
        }

        const incrementedWrNum = results[0].wr_num + 1;

        const dateQuery = `
            SELECT DATE_FORMAT(wr_datetime, "%y-%m-%d") AS formatted_date 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(dateQuery, [incrementedWrNum], (dateError, dateResults) => {
            if (dateError) {
                console.error('쿼리 오류:', dateError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (dateResults.length === 0) {
                return res.status(404).send(' ');
            }

            res.send(dateResults[0].formatted_date);
        });
    });
});


// 출시정보 다음 날짜
app.get('/api/chulndate', (req, res) => {
    const { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    const query = title.length >= 50
        ? `
            SELECT wr_num 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_launch WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_launch WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).send('해당 제목에 대한 wr_num을 찾을 수 없습니다.');
        }

        const incrementedWrNum = results[0].wr_num - 1;

        const dateQuery = `
            SELECT DATE_FORMAT(wr_datetime, "%y-%m-%d") AS formatted_date 
            FROM g5_write_launch 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(dateQuery, [incrementedWrNum], (dateError, dateResults) => {
            if (dateError) {
                console.error('쿼리 오류:', dateError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (dateResults.length === 0) {
                return res.status(404).send(' ');
            }

            res.send(dateResults[0].formatted_date);
        });
    });
});


// 전시일정 이전 글
app.get('/api/junmnum', (req, res) => {
    const { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    const titleLength = title.length;
    const isTitleLong = titleLength >= 50;

    const query = isTitleLong
        ? `
            SELECT wr_num 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_exhibition WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_exhibition WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '해당 제목에 대한 wr_num을 찾을 수 없습니다.' });
        }

        const incrementedWrNum = results[0].wr_num + 1;

        const subjectQuery = `
            SELECT wr_subject 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(subjectQuery, [incrementedWrNum], (subjectError, subjectResults) => {
            if (subjectError) {
                console.error('쿼리 오류:', subjectError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (subjectResults.length === 0) {
                return res.status(404).send(' ');
            }

            res.send(subjectResults[0].wr_subject);
        });
    });
});


// 전시일정 다음글
app.get('/api/junpnum', (req, res) => {
    let { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    const titleLength = title.length;
    const isTitleLong = titleLength >= 50;

    const query = isTitleLong
        ? `
            SELECT wr_num 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_exhibition WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_exhibition
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_exhibition WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: '해당 제목에 대한 wr_num을 찾을 수 없습니다.' });
        }

        const incrementedWrNum = results[0].wr_num - 1;

        const subjectQuery = `
            SELECT wr_subject 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(subjectQuery, [incrementedWrNum], (subjectError, subjectResults) => {
            if (subjectError) {
                console.error('쿼리 오류:', subjectError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (subjectResults.length === 0) {
                return res.status(404).send(' ');
            }

            res.send(subjectResults[0].wr_subject);
        });
    });
});


// 전시일정 이전 날짜
app.get('/api/junmdate', (req, res) => {
    const { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    const query = title.length >= 50
        ? `
            SELECT wr_num 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_exhibition WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_exhibition WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).send('해당 제목에 대한 wr_num을 찾을 수 없습니다.');
        }

        const incrementedWrNum = results[0].wr_num + 1;

        const dateQuery = `
            SELECT DATE_FORMAT(wr_datetime, "%y-%m-%d") AS formatted_date 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(dateQuery, [incrementedWrNum], (dateError, dateResults) => {
            if (dateError) {
                console.error('쿼리 오류:', dateError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (dateResults.length === 0) {
                return res.status(404).send(' ');
            }

            res.send(dateResults[0].formatted_date);
        });
    });
});


// 전시일정 다음 날짜
app.get('/api/junndate', (req, res) => {
    const { title } = req.query;

    if (!title) {
        return res.status(400).json({ message: '제목이 입력되지 않았습니다.' });
    }

    const query = title.length >= 50
        ? `
            SELECT wr_num 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_exhibition WHERE LEFT(wr_subject, 50) = ? LIMIT 1))
        `
        : `
            SELECT wr_num 
            FROM g5_write_exhibition 
            WHERE ABS(wr_num) = ABS((SELECT wr_num FROM g5_write_exhibition WHERE wr_subject = ? LIMIT 1))
        `;

    connection2.query(query, [title], (error, results) => {
        if (error) {
            console.error('쿼리 오류:', error);
            return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
        }

        if (results.length === 0) {
            return res.status(404).send('해당 제목에 대한 wr_num을 찾을 수 없습니다.');
        }

        const incrementedWrNum = results[0].wr_num - 1;

        const dateQuery = `
            SELECT DATE_FORMAT(wr_datetime, "%y-%m-%d") AS formatted_date 
            FROM g5_write_exhibition
            WHERE ABS(wr_num) = ABS(?)
        `;

        connection2.query(dateQuery, [incrementedWrNum], (dateError, dateResults) => {
            if (dateError) {
                console.error('쿼리 오류:', dateError);
                return res.status(500).json({ message: '서버 오류가 발생했습니다.' });
            }

            if (dateResults.length === 0) {
                return res.status(404).send(' ');
            }

            res.send(dateResults[0].formatted_date);
        });
    });
});