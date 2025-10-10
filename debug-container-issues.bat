@echo off
REM Script debug cho container issues trên server backup Windows

echo 🔍 Debugging OrderCheck Container Issues
echo ========================================

REM 1. Kiểm tra containers đang chạy
echo 📋 1. Containers đang chạy:
docker ps -a | findstr ordercheck

echo.
echo 📋 2. Containers bị lỗi (exited):
docker ps -a | findstr "Exited"

echo.
echo 📋 3. Logs của ordercheck-app-v2:
docker logs ordercheck-app-v2 --tail 100

echo.
echo 📋 4. Kiểm tra images:
docker images | findstr ordercheck

echo.
echo 📋 5. Kiểm tra volumes:
docker volume ls | findstr ordercheck

echo.
echo 📋 6. Kiểm tra networks:
docker network ls | findstr ordercheck

echo.
echo 📋 7. Kiểm tra disk space:
wmic logicaldisk get size,freespace,caption

echo.
echo 📋 8. Kiểm tra memory:
wmic OS get TotalVisibleMemorySize,FreePhysicalMemory

echo.
echo 📋 9. Kiểm tra Docker daemon:
docker version

echo.
echo 📋 10. Kiểm tra Docker compose file:
if exist "docker-compose.yml" (
    echo ✅ docker-compose.yml tồn tại
    echo Nội dung:
    type docker-compose.yml
) else (
    echo ❌ docker-compose.yml không tồn tại
)

echo.
echo 📋 11. Kiểm tra .env file:
if exist ".env" (
    echo ✅ .env tồn tại
    echo Nội dung (ẩn sensitive data):
    type .env | findstr /v "SESSION_SECRET="
) else (
    echo ❌ .env không tồn tại
)

echo.
echo 📋 12. Kiểm tra quyền file:
dir | findstr /E "docker-compose .env server.js"

echo.
echo 📋 13. Test MongoDB connection:
docker exec ordercheck-mongodb-v2 mongosh OrderDetailing --eval "db.accounts.countDocuments()" 2>nul || echo ❌ MongoDB không thể kết nối

echo.
echo 📋 14. Kiểm tra port conflicts:
netstat -an | findstr ":3001 :27017"

echo.
echo 🔧 Các lệnh khắc phục:
echo 1. Restart container: docker-compose restart
echo 2. Rebuild container: docker-compose down ^&^& docker-compose up -d --build
echo 3. Clean up: docker system prune -f
echo 4. Check logs: docker logs ordercheck-app-v2 -f

pause
