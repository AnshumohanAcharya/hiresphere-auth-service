const axios = require('axios');

const BASE_URL = 'http://localhost:4000/api/v1/auth';

async function testCookies() {
  try {
    console.log('🧪 Testing cookie functionality...\n');

    // Test 1: Test the test-cookies endpoint
    console.log('1. Testing /test-cookies endpoint...');
    const testResponse = await axios.get(`${BASE_URL}/test-cookies`, {
      withCredentials: true,
    });
    console.log('✅ Test cookies response:', testResponse.data);
    console.log('🍪 Set-Cookie headers:', testResponse.headers['set-cookie']);
    console.log('');

    // Test 2: Test login endpoint (you'll need valid credentials)
    console.log('2. Testing /login endpoint...');
    console.log('⚠️  Note: This requires valid user credentials');
    console.log('   You can register a user first or use existing credentials');
    console.log('');

    // Test 3: Test logout endpoint
    console.log('3. Testing /logout endpoint...');
    console.log('⚠️  Note: This requires a valid JWT token');
    console.log('');

    console.log('📋 To test login/logout:');
    console.log('   1. Register a user: POST /auth/register');
    console.log('   2. Login: POST /auth/login');
    console.log('   3. Check browser dev tools -> Application -> Cookies');
    console.log('   4. Logout: POST /auth/logout');
    console.log('   5. Verify cookies are cleared');
  } catch (error) {
    console.error('❌ Error testing cookies:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
  }
}

// Check if axios is available
try {
  require.resolve('axios');
  testCookies();
} catch (e) {
  console.log('📦 Installing axios for testing...');
  const { execSync } = require('child_process');
  try {
    execSync('npm install axios', { stdio: 'inherit' });
    console.log('✅ Axios installed successfully!');
    testCookies();
  } catch (installError) {
    console.error('❌ Failed to install axios:', installError.message);
    console.log('💡 You can manually install axios: npm install axios');
  }
}
