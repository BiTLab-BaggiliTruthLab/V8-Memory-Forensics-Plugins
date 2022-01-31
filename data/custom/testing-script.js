// This is the code used for the custom data set
// The reason for the sleep is so we can take snapshots
// without worry about the application not running
// this procudes the results for in the notebook
// and found within the paper.
class Animal {
	
	constructor(name, n) {
		this.name = name;
		this.num = n;
	}

	info() {
		return `My Name is ${this.name} and my Instance num is ${this.num}`;
	}


}


async function demo() {
	let anim = new Animal('name1', 0);
	console.log(anim.info());

	let anim2 = new Animal('name2', 1);
	console.log(anim2.info());


	let anim3 = new Animal('name3', 2);
	console.log(anim3.info());

	let anim4 = new Animal('name4', 3);
	console.log(anim4.info());


	let anim5 = new Animal('name5', 4);
	console.log(anim5.info());


	let anim6 = new Animal('name6', 5);
	console.log(anim6.info());

	let anim7 = new Animal('name7', 6);
	console.log(anim7.info());

	let anim8 = new Animal('name8', 7);
	console.log(anim8.info());

	let anim9 = new Animal('name9', 8);
	console.log(anim9.info());

	let anim10 = new Animal('name10', 9);
	console.log(anim10.info());







	await new Promise(r => setTimeout(r, 100000000));
}

demo();
