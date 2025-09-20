#!/bin/bash

# AutoAR Docker Rebuild Script
echo "🔄 Rebuilding AutoAR Docker container..."

# Stop and remove existing container
echo "📦 Stopping existing container..."
docker-compose down 2>/dev/null || true

# Remove old image to force rebuild
echo "🗑️  Removing old image..."
docker rmi autoar-web:dev 2>/dev/null || true

# Build and start new container
echo "🔨 Building new container with all recon tools..."
docker-compose up --build -d

# Wait a moment for container to start
sleep 5

# Check if container is running
if docker ps | grep -q autoar-web; then
    echo "✅ Container started successfully!"
    echo "🌐 Web UI available at: http://localhost:8888"
    echo ""
    echo "📋 Container logs:"
    docker logs autoar-web --tail 20
else
    echo "❌ Container failed to start. Checking logs:"
    docker logs autoar-web
fi
