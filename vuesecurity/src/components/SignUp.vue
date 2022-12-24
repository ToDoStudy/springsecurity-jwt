<template>
  <div class="hello">
    <input type="email" name="" id="" placeholder="Email" v-model="email" />
    <br />
    <input
      type="password"
      name=""
      id=""
      placeholder="password"
      v-model="password"
    />
    <br />
    <select v-model="auth">
      <option disabled value="">메뉴를 선택해 주세요</option>
      <option value="0">사용자</option>
      <option value="1">관리자</option>
    </select>
    <br />
    <input type="submit" value="submit" @click="loginSubmit" />
  </div>
</template>

<script>
import axios from "@/api/http.js";

export default {
  name: "SignUp",
  data() {
    return {
      email: null,
      password: null,
      auth: null,
    };
  },
  methods: {
    loginSubmit() {
      let saveData = {
        email: this.email,
        password: this.password,
        auth: this.auth,
      };

      console.log("value : " + this.auth);

      axios.post("/cmbapart/user/signup", saveData).then((response) => {
        alert("회원가입 성공 : " + response.data.email);
      });
    },
  },
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}
ul {
  list-style-type: none;
  padding: 0;
}
li {
  display: inline-block;
  margin: 0 10px;
}
a {
  color: #42b983;
}
</style>
