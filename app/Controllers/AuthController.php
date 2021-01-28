<?php

namespace App\Controllers;

use App\Models\AuthModel;

class AuthController extends BaseController
{
    public function __construct()
    {
        $this->model = new AuthModel();
    }

    public function registrasi()
    {
        $data = [
            'validation' => \config\Services::validation()
        ];

        return view('auth/registrasi', $data);
    }

    public function simpanRegistrasi() 
    {

        /* Validasi Sebelum simpan data dengan function rulesRegistrasi */
        if ($this->validate($this->rulesRegistrasi()))  {
            $this->model->save([
                'name' => $this->request->getPost('name'),
                'email' => $this->request->getPost('email'),
                'password' => password_hash($this->request->getPost('password'), PASSWORD_BCRYPT),
                'role' => 'siswa',
            ]);
    
            /*
            | set session flash (one time session) sebagai pesan registrasi berhasil
            | yang di tampung di dalam variable 'registrasi_sukses'
            */
            session()->setFlashdata('registrasi_sukses', 'Registrasi berhasil');
    
            /* redirect tetap ke halaman registrasi, untuk menunjukan pesan resgitrasi berhasil */
            return redirect()->to('/registrasi');
                
        } else {
            /*
            | apabila inputan tidak valid dengan aturan rulesRegistrasi
            | redirect kehalaman registrasi dengan inputan datanya, sehingga inputan 
            | yang sudah benar terinput tidak hilang
            */
            return redirect()->to('/registrasi')->withInput();
        }
    }

    public function rulesRegistrasi()
    {
        $setRules = [
            'name' =>  [
                'rules' => 'required',
                'errors' => [
                'required' => 'Nama Harus Di Isi'
                ]
            ],
            'email' => [
                'rules' => 'required|valid_email|is_unique[users.email]',
                'errors' => [
                    'required' => 'Email Harus Di Isi',
                    'valid_email' => 'Email Anda Tidak Valid',
                    'is_unique' => 'Email {value} Sudah Ada',
                ]
            ],
            'password' => [
                'rules' => 'required|min_length[8]',
                'errors' => [
                    'required' => 'Password Harus Di Isi',
                    'min_length' => 'Password Minimal {param} Karakter',
                ]
            ],
            'konfirmasi_password' => [
                'rules' => 'required|matches[password]',
                'errors' => [
                    'required' => 'Konfirmasi Password Harus Di Isi',
                    'matches' => 'Konfirmasi Password Berbeda Dengan {param}',
                ]
            ],
        ];
        return $setRules;
    }
    
    public function login()
    {
        $data = [
            'validation' => \config\Services::validation()
        ];
        return view ('auth/login', $data);
    }

    public function prosesLogin()
    {
        if ($this->validate($this->rulesLogin())) {
            $query = $this->model->where('email', $this->request->getPost('email'));
            $count = $query->countAllResults(false);
            $data = $query->get()->getRow();

            if ($count > 0) {

                $hashPassword = $data->password;

                if (password_verify($this->request->getPost('password'), $hashPassword)) {
                   
                    $session = [
                        'role' => $data->role,
                        'logged_in' => TRUE
                    ];
                    session()->set($session);
                    
                    return redirect()->to(base_url('home'));
                } else {
                    return redirect()->to(base_url('login'))->with('login_failed', 'Username Atau Password Salah');
                }
            } else {
                return redirect()->to(base_url('login'))->with('login_failed', 'Username Tidak Ditemukan');
            }
        } else {
            return redirect()->to(base_url('login'))->withInput();
        }
    }

    public function rulesLogin()
    {
        $setRules = [
            'email' => [
                'rules' => 'required|valid_email',
                'errors' => [
                    'required' => 'Email Harus Diisi',
                    'valid_email' => 'Email Anda Tidak Valid',
                ]

            ],
            'password' => [
                'rules' => 'required',
                'errors' => [
                    'required' => 'Password Harus Diisi',
                ]
            ]
        ];

        return $setRules;
    }

    public function logout()
    {
        session()->destroy();
        return redirect()->to('/login');
    }
}