const bcrypt = require('bcrypt');
const { authenticator } = require('otplib');

const users = [
  { username: 'admin', password: 'P@ssw0rd!', role: 'admin' },
  { username: 'operator', password: 'Operate123', role: 'operator' },
  { username: 'viewer', password: 'ViewOnly1', role: 'viewer' }
];

(async () => {
  for (const user of users) {
    const hash = await bcrypt.hash(user.password, 10);
    console.log(
      JSON.stringify({
        username: user.username,
        passwordHash: hash,
        role: user.role,
        totpSecret: authenticator.generateSecret()
      })
    );
  }
})();
